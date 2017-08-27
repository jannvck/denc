package denc

import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.FilterInputStream
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.charset.StandardCharsets
import java.nio.file.Paths
import java.nio.file.StandardOpenOption
import java.util.Properties

import scala.collection.mutable.ArrayBuffer

import org.apache.commons.crypto.random.CryptoRandomFactory
import org.apache.commons.crypto.stream.CryptoInputStream
import org.apache.commons.crypto.stream.CryptoOutputStream

import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import scalafx.Includes._
import scalafx.application.JFXApp
import scalafx.scene.Scene
import scalafx.scene.control.PasswordField
import scalafx.scene.control.ProgressBar
import scalafx.scene.input.DragEvent
import scalafx.scene.input.TransferMode
import scalafx.scene.layout.BorderPane
import scalafx.scene.layout.StackPane
import scalafx.scene.paint.Color
import scalafx.scene.shape.Rectangle
import scalafx.scene.text.Text
import java.util.zip.CheckedInputStream
import java.util.zip.CRC32
import java.util.zip.CheckedOutputStream
import scalafx.scene.control.Alert
import scalafx.scene.control.Alert.AlertType
import scalafx.application.Platform

object DEnc extends JFXApp {
  private case class DerivedData(key: Array[Byte], salt: Array[Byte])
  private case class Metadata private (
      filename: String, // FIXME maybe this is a security issue
      iv: Array[Byte],
      salt: Array[Byte],
      encryptedSize: Long, // FIXME storing encrypted size and metadata size is unnecessary redundancy
      checksum: Long,
      metadataSize: Int,
      metadataVersion: Int,
      metadataChecksum: Long) {
    def writeTo(file: File): Long = {
      val encryptedSize = file.length()
      val fileOutputStream = new FileOutputStream(file, true)
      val checkedOutputStream = new CheckedOutputStream(fileOutputStream, new CRC32())
      val filnameBytes = filename.getBytes(StandardCharsets.UTF_8)
      checkedOutputStream.write(ByteBuffer.allocate(4).putInt(Metadata.VERSION).array())
      checkedOutputStream.write(ByteBuffer.allocate(4).putInt(filnameBytes.length).array())
      checkedOutputStream.write(filnameBytes)
      checkedOutputStream.write(ByteBuffer.allocate(4).putInt(iv.length).array())
      checkedOutputStream.write(iv)
      checkedOutputStream.write(ByteBuffer.allocate(4).putInt(salt.length).array())
      checkedOutputStream.write(salt)
      checkedOutputStream.write(ByteBuffer.allocate(8).putLong(encryptedSize).array())
      checkedOutputStream.write(ByteBuffer.allocate(8).putLong(checksum).array())
      val metadataSize = filnameBytes.length + iv.length + salt.length + 11 * 4
      checkedOutputStream.write(ByteBuffer.allocate(4).putInt(metadataSize).array())
      checkedOutputStream.flush()
      checkedOutputStream.write(ByteBuffer.allocate(8).putLong(checkedOutputStream.getChecksum.getValue).array())
      checkedOutputStream.flush()
      checkedOutputStream.close()
      fileOutputStream.flush()
      fileOutputStream.close()
      return metadataSize
    }
  }
  private object Metadata {
    val VERSION = 1
    def apply(file: File): Metadata = {
      val fileChannel = FileChannel.open(Paths.get(file.getPath), StandardOpenOption.READ)
      fileChannel.position(fileChannel.size() - (4 + 8)) // metadata checksum comes last
      val dataMetaDataLength = ByteBuffer.allocate(4)
      fileChannel.read(dataMetaDataLength)
      val metadataPosition = fileChannel.size() - dataMetaDataLength.getInt(0)
      fileChannel.position(metadataPosition)
      val dataMetadataVersion = ByteBuffer.allocate(4)
      fileChannel.read(dataMetadataVersion)
      if (dataMetadataVersion.getInt(0) != VERSION) throw new RuntimeException("Invalid metadata version detected")
      val dataFileNameLength = ByteBuffer.allocate(4)
      fileChannel.read(dataFileNameLength)
      val dataFileName = ByteBuffer.allocate(dataFileNameLength.getInt(0))
      fileChannel.read(dataFileName)
      val dataIvLength = ByteBuffer.allocate(4)
      fileChannel.read(dataIvLength)
      val dataIv = ByteBuffer.allocate(dataIvLength.getInt(0))
      fileChannel.read(dataIv)
      val dataSaltLength = ByteBuffer.allocate(4)
      fileChannel.read(dataSaltLength)
      val dataSalt = ByteBuffer.allocate(dataSaltLength.getInt(0))
      fileChannel.read(dataSalt)
      val dataEncryptedFilesize = ByteBuffer.allocate(8)
      fileChannel.read(dataEncryptedFilesize)
      val dataChecksum = ByteBuffer.allocate(8)
      fileChannel.read(dataChecksum)
      // check metadata for corruption
      val metadata = ByteBuffer.allocate(dataMetaDataLength.getInt(0) - 8) // exclude the checksum itself
      fileChannel.position(metadataPosition)
      fileChannel.read(metadata)
      val dataMetadataChecksum = ByteBuffer.allocate(8)
      fileChannel.read(dataMetadataChecksum)
      val metadataChecksum = new CRC32()
      metadataChecksum.update(metadata.array())
      if (metadataChecksum.getValue != dataMetadataChecksum.getLong(0)) throw new RuntimeException("Metadata corrupted")
      return Metadata(
        new String(dataFileName.array(), StandardCharsets.UTF_8),
        dataIv.array(),
        dataSalt.array(),
        dataEncryptedFilesize.getLong(0),
        dataChecksum.getLong(0),
        dataMetaDataLength.getInt(0),
        dataMetadataVersion.getInt(0),
        dataMetadataChecksum.getLong(0))
    }
  }
  val progressBar = new ProgressBar {
    prefWidth = 400
    progress = 0.0d
  }
  def droppingRectangle[R](f: Seq[File] => R) = new Rectangle {
    width = 200
    height = 200
    fill = Color.Grey
    onDragOver = (de: DragEvent) => {
      fill = Color.Green
      de.acceptTransferModes(TransferMode("COPY"))
      de.consume()
    }
    onDragExited = (de: DragEvent) => {
      fill = Color.Grey
      de.consume()
    }
    onDragDropped = (de: DragEvent) => {
      val content = de.dragboard.content
      if (content.hasFiles) {
        val thread = new Thread(new Runnable {
          override def run() = {
            try {
              f(content.files)
            } catch {
              case e: Exception => Platform.runLater {
                new Alert(AlertType.Error) {
                  initOwner(stage)
                  title = "Warning"
                  headerText = "Operation failed"
                  contentText = e.getMessage
                }.showAndWait()
              }
            }
          }
        })
        thread.setDaemon(true)
        thread.start()
        de.setDropCompleted(true)
      } else {
        de.setDropCompleted(false)
      }
      de.consume()
    }
  }
  val droppingRectangleEncryption = droppingRectangle(encrypt)
  val droppingRectangleDecryption = droppingRectangle(decrypt)
  val passwordField = new PasswordField {
    promptText = "Enter password"
    prefWidth = 400
  }
  stage = new JFXApp.PrimaryStage {
    title.value = "DEnc"
    resizable = false
    scene = new Scene {
      content = new BorderPane {
        top = passwordField
        left = new StackPane {
          children = Seq(droppingRectangleEncryption,
            new Text {
              text = "Place object to\nencrypt here"
              fill = Color.White
            })
        }
        right = new StackPane {
          children = Seq(droppingRectangleDecryption,
            new Text {
              text = "Place object to\ndecrypt here"
              fill = Color.White
            })
        }
        bottom = progressBar
      }
    }
  }
  stage.sizeToScene()
  def encrypt(files: Seq[File]): Long = {
    val totalBytes = files(0).length()
    println("Encrypting " + files(0) + " (" + totalBytes + " bytes) ...")

    val salt = randomBytes(16)
    val derivedKey = deriveKeyFrom(passwordField.text.value.toCharArray(), salt)
    val key = new SecretKeySpec(derivedKey.key, "AES");
    val plainIv = randomBytes(16)
    val iv = new IvParameterSpec(plainIv);
    val properties = new Properties()
    val transform = "AES/CBC/PKCS5Padding"

    var encryptedFile: File = null
    var fileOutputStream: FileOutputStream = null
    var cryptoOutputStream: CryptoOutputStream = null
    var fileInputStream: FileInputStream = null
    var checkedInputStream: CheckedInputStream = null
    try {
      encryptedFile = new File(files(0).getAbsolutePath + ".enc")
      fileOutputStream = new FileOutputStream(encryptedFile)
      cryptoOutputStream = new CryptoOutputStream(transform, properties, fileOutputStream, key, iv)
      fileInputStream = new FileInputStream(files(0))
      checkedInputStream = new CheckedInputStream(fileInputStream, new CRC32())
      var totalBytesRead = 0
      var currentBytesRead = 0
      val data = ArrayBuffer.fill(1024)(0.toByte).toArray
      while (currentBytesRead > -1) {
        currentBytesRead = checkedInputStream.read(data, 0, 1024)
        if (currentBytesRead > -1) {
          totalBytesRead += currentBytesRead
          cryptoOutputStream.write(data, 0, currentBytesRead)
        }
        setProgress(totalBytes, totalBytesRead)
      }
    } catch {
      case e: Exception => throw e
    } finally {
      if (cryptoOutputStream != null) {
        cryptoOutputStream.flush()
        cryptoOutputStream.close()
      }
      if (fileOutputStream != null) {
        fileOutputStream.flush()
        fileOutputStream.close()
      }
      if (fileInputStream != null) {
        fileInputStream.close()
      }
      if (checkedInputStream != null) {
        checkedInputStream.close()
      }
    }
    val meta = Metadata(
      files(0).getName,
      plainIv,
      salt,
      totalBytes,
      checkedInputStream.getChecksum.getValue,
      -1, // size is calculated and overwritten upon write
      -1, // metadata version is overwritten upon write
      -1) // checksum is calculated and overwritten upon write
    println("IV:\t" + meta.iv.mkString(" "))
    println("Salt:\t" + meta.salt.mkString(" "))
    println("CRC32:\t" + meta.checksum)
    println("Metadata size:\t" + meta.writeTo(encryptedFile) + " bytes")
    return meta.checksum
  }
  def decrypt(files: Seq[File]): Long = {
    println("Decrypting " + files(0) + " (" + files(0).length() + " bytes) ...")

    val metadata = Metadata(files(0))
    val totalBytes = metadata.encryptedSize
    println("Filename:\t" + metadata.filename)
    println("Encrypted size:\t" + metadata.encryptedSize + " bytes")
    println("IV:\t" + metadata.iv.mkString(" "))
    println("Salt:\t" + metadata.salt.mkString(" "))
    println("CRC32:\t" + metadata.checksum)
    println("Metadata version:\t" + metadata.metadataVersion)
    println("Metadata size:\t" + metadata.metadataSize + " bytes")

    val derivedKey = deriveKeyFrom(passwordField.text.value.toCharArray(), metadata.salt)
    val key = new SecretKeySpec(derivedKey.key, "AES");
    val iv = new IvParameterSpec(metadata.iv);
    val properties = new Properties()
    val transform = "AES/CBC/PKCS5Padding"

    var fileInputStream: FileInputStream = null
    var cutoffInputStream: CutoffInputStream = null
    var cryptoInputStream: CryptoInputStream = null
    var fileOutputStream: FileOutputStream = null
    var checkedOutputStream: CheckedOutputStream = null
    try {
      fileInputStream = new FileInputStream(files(0))
      cutoffInputStream = new CutoffInputStream(fileInputStream, metadata.encryptedSize)
      cryptoInputStream = new CryptoInputStream(transform, properties, cutoffInputStream, key, iv)
      fileOutputStream = new FileOutputStream(new File(metadata.filename + ".dec"))
      checkedOutputStream = new CheckedOutputStream(fileOutputStream, new CRC32())
      val data = ByteBuffer.allocate(1024).array()
      var totalBytesRead = 0
      var currentBytesRead = 0
      while (currentBytesRead > -1) {
        currentBytesRead = cryptoInputStream.read(data)
        if (currentBytesRead > -1) {
          totalBytesRead += currentBytesRead
          checkedOutputStream.write(data, 0, currentBytesRead)
        }
        setProgress(totalBytes, totalBytesRead)
      }
    } catch {
      case e: Exception => throw e
    } finally {
      if (fileOutputStream != null) {
        fileOutputStream.flush()
        fileOutputStream.close()
      }
      if (checkedOutputStream != null) {
        checkedOutputStream.flush()
        checkedOutputStream.close()
      }
      if (cryptoInputStream != null) {
        cryptoInputStream.close()
      }
      if (cutoffInputStream != null) {
        cutoffInputStream.close()
      }
      if (fileInputStream != null) {
        fileInputStream.close()
      }
    }
    if (checkedOutputStream.getChecksum.getValue != metadata.checksum) throw new RuntimeException("File corrupted")
    return checkedOutputStream.getChecksum.getValue
  }
  private def randomBytes(amount: Int): Array[Byte] = {
    val data = ArrayBuffer.fill(amount)(0.toByte).toArray
    CryptoRandomFactory.getCryptoRandom().nextBytes(data)
    return data
  }
  private def deriveKeyFrom(password: Array[Char], salt: Array[Byte]): DerivedData = {
    val spec = new PBEKeySpec(password, salt, 65536, 128); // AES-128
    val secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
    return DerivedData(secretKeyFactory.generateSecret(spec).getEncoded(), salt)
  }
  private def setProgress(total: Long, current: Long) = progressBar.progress = 1.0d / total.toDouble * current.toDouble
}
class CutoffInputStream(is: InputStream, maxBytes: Long) extends FilterInputStream(is) {
  private var totalBytesRead: Long = 0
  override def read(): Int = {
    if (totalBytesRead < maxBytes) {
      totalBytesRead += 1
      return in.read()
    } else {
      return -1
    }
  }
  override def read(array: Array[Byte], offset: Int, length: Int): Int = {
    if (totalBytesRead < maxBytes) {
      if (totalBytesRead + length <= maxBytes) { // all fits in total maximum
        val currentBytesRead = in.read(array, offset, length)
        totalBytesRead += currentBytesRead
        return currentBytesRead
      } else { // only a portion will be written
        val currentBytesRead = in.read(array, offset, (maxBytes - totalBytesRead).toInt)
        totalBytesRead += currentBytesRead
        return currentBytesRead
      }
    } else { // reached the limit, so cut off
      return -1
    }
  }
}