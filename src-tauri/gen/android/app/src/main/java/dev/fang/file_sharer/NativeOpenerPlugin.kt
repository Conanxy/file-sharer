package dev.fang.file_sharer

import android.app.Activity
import android.content.ContentValues
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.webkit.MimeTypeMap
import androidx.core.content.FileProvider
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.io.File

@InvokeArg
class OpenPathArgs {
  lateinit var path: String
}

@InvokeArg
class OpenUriArgs {
  lateinit var uri: String
}

@TauriPlugin
class NativeOpenerPlugin(private val activity: Activity) : Plugin(activity) {
  @Command
  fun openPath(invoke: Invoke) {
    try {
      val args = invoke.parseArgs(OpenPathArgs::class.java)
      val file = File(args.path)
      if (!file.exists() || !file.isFile) {
        invoke.reject("文件不存在")
        return
      }

      val uri = FileProvider.getUriForFile(
        activity,
        "${activity.packageName}.fileprovider",
        file
      )
      val intent = Intent(Intent.ACTION_VIEW).apply {
        setDataAndType(uri, mimeType(file, uri))
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
      }

      activity.startActivity(intent)
      invoke.resolve()
    } catch (ex: Exception) {
      invoke.reject(ex.message ?: "打开失败")
    }
  }

  @Command
  fun openUri(invoke: Invoke) {
    try {
      val args = invoke.parseArgs(OpenUriArgs::class.java)
      val uri = Uri.parse(args.uri)
      openContentUri(uri, activity.contentResolver.getType(uri) ?: "application/octet-stream")
      invoke.resolve()
    } catch (ex: Exception) {
      invoke.reject(ex.message ?: "打开失败")
    }
  }

  @Command
  fun openDownloads(invoke: Invoke) {
    try {
      val intent = Intent(DownloadManagerAction).apply {
        addCategory(Intent.CATEGORY_DEFAULT)
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
      }
      activity.startActivity(intent)
      invoke.resolve()
    } catch (_: Exception) {
      try {
        activity.startActivity(Intent(Intent.ACTION_VIEW).apply {
          setDataAndType(Uri.parse("content://com.android.externalstorage.documents/root/primary"), "vnd.android.document/root")
          addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        })
        invoke.resolve()
      } catch (ex: Exception) {
        invoke.reject(ex.message ?: "打开下载目录失败")
      }
    }
  }

  @Command
  fun publishToDownloads(invoke: Invoke) {
    try {
      val args = invoke.parseArgs(OpenPathArgs::class.java)
      val source = File(args.path)
      if (!source.exists() || !source.isFile) {
        invoke.reject("文件不存在")
        return
      }

      val displayName = uniqueDisplayName(source.name)
      val mimeType = mimeType(source, Uri.fromFile(source))
      val values = ContentValues().apply {
        put(MediaStore.Downloads.DISPLAY_NAME, displayName)
        put(MediaStore.Downloads.MIME_TYPE, mimeType)
        put(MediaStore.Downloads.RELATIVE_PATH, "${Environment.DIRECTORY_DOWNLOADS}/File Sharer")
        put(MediaStore.Downloads.SIZE, source.length())
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
          put(MediaStore.Downloads.IS_PENDING, 1)
        }
      }

      val resolver = activity.contentResolver
      val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
        ?: throw IllegalStateException("无法创建下载文件")
      try {
        resolver.openOutputStream(uri)?.use { output ->
          source.inputStream().use { input -> input.copyTo(output) }
        } ?: throw IllegalStateException("无法写入下载文件")

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
          val finished = ContentValues().apply {
            put(MediaStore.Downloads.IS_PENDING, 0)
          }
          resolver.update(uri, finished, null, null)
        }
      } catch (ex: Exception) {
        resolver.delete(uri, null, null)
        throw ex
      }

      val result = JSObject().apply {
        put("uri", uri.toString())
      }
      invoke.resolve(result)
    } catch (ex: Exception) {
      invoke.reject(ex.message ?: "保存到下载目录失败")
    }
  }

  private fun openContentUri(uri: Uri, mimeType: String) {
    val intent = Intent(Intent.ACTION_VIEW).apply {
      setDataAndType(uri, mimeType)
      addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
      addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }

    activity.startActivity(intent)
  }

  private fun mimeType(file: File, uri: Uri): String {
    val extension = file.extension.lowercase()
    return MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension)
      ?: activity.contentResolver.getType(uri)
      ?: "application/octet-stream"
  }

  private fun uniqueDisplayName(fileName: String): String {
    val resolver = activity.contentResolver
    val dot = fileName.lastIndexOf('.')
    val stem = if (dot > 0) fileName.substring(0, dot) else fileName
    val extension = if (dot > 0) fileName.substring(dot) else ""

    for (index in 0 until 10_000) {
      val candidate = if (index == 0) fileName else "$stem ($index)$extension"
      val projection = arrayOf(MediaStore.Downloads._ID)
      val selection = "${MediaStore.Downloads.DISPLAY_NAME}=? AND ${MediaStore.Downloads.RELATIVE_PATH}=?"
      val args = arrayOf(candidate, "${Environment.DIRECTORY_DOWNLOADS}/File Sharer/")
      resolver.query(MediaStore.Downloads.EXTERNAL_CONTENT_URI, projection, selection, args, null).use { cursor ->
        if (cursor == null || !cursor.moveToFirst()) {
          return candidate
        }
      }
    }

    return "${stem}-${System.currentTimeMillis()}$extension"
  }

  companion object {
    private const val DownloadManagerAction = "android.intent.action.VIEW_DOWNLOADS"
  }
}
