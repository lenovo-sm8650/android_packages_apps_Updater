/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */
package net.pixelos.ota.data.source.network

import android.content.Context
import android.os.SystemProperties
import android.util.Base64
import kotlinx.serialization.json.Json
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import net.pixelos.ota.R
import net.pixelos.ota.deviceinfo.DeviceInfoUtils
import java.io.IOException
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.concurrent.TimeUnit

class UpdatesNetworkDataSource(private val context: Context) {
    private val serverUrl: String
        get() {
            val base = context.getString(R.string.updater_server_url)
            require(base.startsWith("https://")) {
                "Update server URL must use HTTPS: $base"
            }
            require(DeviceInfoUtils.device.isNotBlank()) {
                "Missing ro.custom.device"
            }
            require(DeviceInfoUtils.otaBranch.isNotBlank()) {
                "Missing net.pixelos.version"
            }
            require(DeviceInfoUtils.buildType.isNotBlank()) {
                "Missing net.pixelos.build_type"
            }
            return base
                .replace("{device}", DeviceInfoUtils.device)
                .replace("{branch}", DeviceInfoUtils.otaBranch)
        }

    private val client = OkHttpClient.Builder()
        .callTimeout(10, TimeUnit.SECONDS)
        .followRedirects(false)
        .followSslRedirects(false)
        .build()

    fun fetchUpdates(): List<NetworkUpdate> {
        val url = serverUrl
        if (isSourceForgeFolder(url)) return fetchSourceForgeFolder(url)
        return Json.decodeFromString<List<NetworkUpdate>>(fetch(url).decodeToString())
            .onEach { it.validate() }
    }

    /**
     * SourceForge folder mode (updater_server_url is the RSS feed of the folder,
     * https://sourceforge.net/projects/<project>/rss?path=<dir>): every build has its own
     * folder <dir>/<yyyyMMdd-HHmm>/ with "<package>.json" (the usual update list), its
     * incremental package and "<package>.json.sig" when a signing key is configured. The full
     * package is the recovery package of the release, kept once in the release folder
     * <dir>/../<yyyyMMdd-HHmm>/ (e.g. seventeen/OTA/20260930-0251/ and seventeen/20260930-0251/).
     * The newest build folder with a description for this device's package variant is used;
     * the repository shows it only when it is newer than the running build.
     *
     * Security: the feed URL and the signing key come from this app's resources (system
     * partition, verified boot); everything is fetched over HTTPS from sourceforge.net only;
     * links must stay in the project folder; with updater_signing_public_key set, the
     * description must carry a valid Ed25519 signature of that key; the packages must be files
     * of that build's folders and a downloaded package's SHA-256 is checked
     * (UpdaterController).
     */
    private fun isSourceForgeFolder(url: String) =
        url.startsWith("https://sourceforge.net/projects/") && url.contains("/rss")

    private fun fetchSourceForgeFolder(feedUrl: String): List<NetworkUpdate> {
        val project = feedUrl.removePrefix("https://sourceforge.net/projects/").substringBefore('/')
        require(project.matches(PROJECT_REGEX)) { "Invalid SourceForge project: $project" }
        val filesPrefix = "https://sourceforge.net/projects/$project/files/"

        val variant = SystemProperties.get(PROP_VARIANT)
        require(variant == "PRC" || variant == "ROW") { "Unknown package variant: '$variant'" }

        val feed = fetch(feedUrl).decodeToString()
        val newest = LINK_REGEX.findAll(feed)
            .map { it.groupValues[1] }
            .filter { it.startsWith(filesPrefix) && !it.contains("..") }
            .map { it.removeSuffix("/download") }
            .filter { path ->
                val name = path.substringAfterLast('/')
                val match = NAME_REGEX.matchEntire(name) ?: return@filter false
                // <dir>/<yyyyMMdd-HHmm>/<package>.json, folder named after the build
                path.substringBeforeLast('/').substringAfterLast('/') == match.groupValues[2] &&
                    match.groupValues[1] == DeviceInfoUtils.device &&
                    (match.groupValues[3] == "-ROW") == (variant == "ROW")
            }
            .maxByOrNull { NAME_REGEX.matchEntire(it.substringAfterLast('/'))!!.groupValues[2] }
            ?: return emptyList()

        val json = fetch("$newest/download")
        val key = context.getString(R.string.updater_signing_public_key).trim()
        if (key.isNotEmpty()) {
            val signature = fetch("$newest.sig/download")
            require(verifySignature(key, json, signature)) { "Bad signature for $newest" }
        }

        // <dir>/<build> holds the description and the incremental, <dir>/../<build> the full
        // package of the release
        val buildFolder = newest.substringBeforeLast('/')
        val build = buildFolder.substringAfterLast('/')
        val releaseFolder = buildFolder.substringBeforeLast('/').substringBeforeLast('/') +
            "/" + build
        return Json.decodeFromString<List<NetworkUpdate>>(json.decodeToString()).onEach { update ->
            update.validate()
            update.files.forEach { file ->
                require(
                    !file.filename.contains('/') &&
                        file.url == "$releaseFolder/${file.filename}/download"
                ) {
                    "Full package URL outside the release folder: ${file.url}"
                }
            }
            update.incremental.orEmpty().forEach { file ->
                require(
                    !file.filename.contains('/') &&
                        file.url == "$buildFolder/${file.filename}/download"
                ) {
                    "Incremental package URL outside the build folder: ${file.url}"
                }
            }
        }
    }

    /** Ed25519 signature (raw 64 bytes or Base64) of [data] with [key] (Base64 X.509). */
    private fun verifySignature(key: String, data: ByteArray, signature: ByteArray): Boolean {
        return try {
            val publicKey = KeyFactory.getInstance("Ed25519")
                .generatePublic(X509EncodedKeySpec(Base64.decode(key, Base64.DEFAULT)))
            val sig = if (signature.size == 64) {
                signature
            } else {
                Base64.decode(signature.decodeToString().trim(), Base64.DEFAULT)
            }
            Signature.getInstance("Ed25519").run {
                initVerify(publicKey)
                update(data)
                verify(sig)
            }
        } catch (e: Exception) {
            false
        }
    }

    /**
     * HTTPS GET with the redirects (SourceForge sends downloads to its mirrors) followed by
     * hand: only to HTTPS and only within sourceforge.net for the SourceForge mode.
     */
    private fun fetch(startUrl: String): ByteArray {
        var url = startUrl
        repeat(MAX_REDIRECTS) {
            val request = Request.Builder()
                .url(url)
                .build()
            val next = client.newCall(request).execute().use { response ->
                if (response.isRedirect) {
                    val location = response.header("Location")
                        ?: throw IOException("Redirect without location")
                    val target = response.request.url.resolve(location)
                        ?: throw IOException("Bad redirect: $location")
                    if (!target.isHttps || !isAllowedRedirectHost(target.host)) {
                        throw IOException("Refusing redirect to $target")
                    }
                    return@use target.toString()
                }
                if (!response.isSuccessful) {
                    throw IOException("Unexpected HTTP status: ${response.code}")
                }

                val body = response.body ?: throw IOException("Empty response body")
                val contentLength = body.contentLength()
                if (contentLength > MAX_RESPONSE_BYTES) {
                    throw IOException("Update response is too large: $contentLength bytes")
                }
                val source = body.source()
                val hasMore = source.request(MAX_RESPONSE_BYTES + 1)
                if (hasMore) {
                    throw IOException("Update response exceeds $MAX_RESPONSE_BYTES bytes")
                }
                return source.buffer.readByteArray()
            }
            url = next
        }
        throw IOException("Too many redirects: $startUrl")
    }

    private fun isAllowedRedirectHost(host: String) =
        isSourceForgeFolder(serverUrl) &&
            (host == "sourceforge.net" || host.endsWith(".sourceforge.net"))

    private companion object {
        const val MAX_RESPONSE_BYTES = 1024L * 1024L
        const val MAX_REDIRECTS = 5

        /** Package variant of the running build (dtb region), set by the device. */
        const val PROP_VARIANT = "ro.vendor.tb520fu.dtb_region"

        val PROJECT_REGEX = Regex("[a-z0-9][a-z0-9-]*")

        /** <link> of an RSS item. */
        val LINK_REGEX = Regex("<link>(https://[^<]+/download)</link>")

        /** PixelOS_<device>-<version>-<yyyyMMdd-HHmm>[-ROW].json */
        val NAME_REGEX =
            Regex("PixelOS_([A-Za-z0-9_]+)-[0-9.]+-(\\d{8}-\\d{4})(-ROW)?\\.json")
    }
}
