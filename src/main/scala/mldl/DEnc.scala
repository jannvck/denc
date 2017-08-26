package mldl

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
import scalafx.Includes.eventClosureWrapperWithParam
import scalafx.Includes.jfxDragEvent2sfx
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

object DEnc extends JFXApp {
  private case class DerivedKey(key: Array[Byte], salt: Array[Byte])
  private case class MetaData private (
      filename: String,
      iv: Array[Byte],
      salt: Array[Byte],
      encryptedSize: Long,
      metadataSize: Int,
      metadataVersion: Int) {
    def writeTo(file: File): Long = {
      val encryptedSize = file.length()
      val fileOutputStream = new FileOutputStream(file, true)
      val filnameBytes = filename.getBytes(StandardCharsets.UTF_8)
      fileOutputStream.write(ByteBuffer.allocate(4).putInt(filnameBytes.length).array())
      fileOutputStream.write(filnameBytes)
      fileOutputStream.write(ByteBuffer.allocate(4).putInt(iv.length).array())
      fileOutputStream.write(iv)
      fileOutputStream.write(ByteBuffer.allocate(4).putInt(salt.length).array())
      fileOutputStream.write(salt)
      fileOutputStream.write(ByteBuffer.allocate(4).putInt(metadataVersion).array())
      fileOutputStream.write(ByteBuffer.allocate(8).putLong(encryptedSize).array())
      val metadataSize = filnameBytes.length + iv.length + salt.length + 7 * 4
      fileOutputStream.write(ByteBuffer.allocate(4).putInt(metadataSize).array())
      fileOutputStream.flush()
      fileOutputStream.close()
      return metadataSize
    }
  }
  private object MetaData {
    def apply(file: File): MetaData = {
      val fileChannel = FileChannel.open(Paths.get(file.getPath), StandardOpenOption.READ)
      fileChannel.position(fileChannel.size() - 4)
      val dataMetaDataLength = ByteBuffer.allocate(4)
      fileChannel.read(dataMetaDataLength)
      fileChannel.position(fileChannel.size() - dataMetaDataLength.getInt(0))
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
      val dataMetadataVersion = ByteBuffer.allocate(4)
      fileChannel.read(dataMetadataVersion)
      val dataEncryptedFilesize = ByteBuffer.allocate(8)
      fileChannel.read(dataEncryptedFilesize)
      return MetaData(
        new String(dataFileName.array(), StandardCharsets.UTF_8),
        dataIv.array(),
        dataSalt.array(),
        dataEncryptedFilesize.getLong(0),
        dataMetaDataLength.getInt(0),
        dataMetadataVersion.getInt(0))
    }
  }
  val progressBar = new ProgressBar {
    prefWidth = 400
    progress = 0.0d
  }
  def droppingRectangle(f: Seq[File] => Unit) = new Rectangle {
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
            f(content.files)
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
    promptText = "enter password"
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
  def encrypt(files: Seq[File]) = {
    val totalBytes = files(0).length()
    println("encrypting " + files(0) + " (" + totalBytes + " bytes) ...")

    val salt = randomBytes(16)
    val derivedKey = deriveKeyFrom(passwordField.text.value.toCharArray(), salt)
    val key = new SecretKeySpec(derivedKey.key, "AES");
    val plainIv = randomBytes(16)
    val iv = new IvParameterSpec(plainIv);
    val properties = new Properties()
    val transform = "AES/CBC/PKCS5Padding"

    val encryptedFile = new File(files(0).getAbsolutePath + ".enc")
    val fileOutputStream = new FileOutputStream(encryptedFile)
    val cryptoOutputStream = new CryptoOutputStream(transform, properties, fileOutputStream, key, iv)
    val fileInputStream = new FileInputStream(files(0))
    var totalBytesRead = 0
    var currentBytesRead = 0
    val data = ArrayBuffer.fill(1024)(0.toByte).toArray
    while (currentBytesRead > -1) {
      currentBytesRead = fileInputStream.read(data, 0, 1024)
      if (currentBytesRead > -1) {
        totalBytesRead += currentBytesRead
        cryptoOutputStream.write(data, 0, currentBytesRead)
      }
      setProgress(totalBytes, totalBytesRead)
    }
    cryptoOutputStream.flush()
    cryptoOutputStream.close()
    fileOutputStream.flush()
    fileOutputStream.close()
    fileInputStream.close()
    val meta = MetaData(files(0).getName, plainIv, salt, totalBytes, -1, 1) // size is calculated upon write
    println("IV:\t" + meta.iv.mkString(""))
    println("Salt:\t" + meta.salt.mkString(""))
    println("wrote additional " + meta.writeTo(encryptedFile) + " bytes of metadata")
  }
  def decrypt(files: Seq[File]) = {
    println("decrypting " + files(0) + " (" + files(0).length() + " bytes) ...")

    val metadata = MetaData(files(0))
    val totalBytes = metadata.encryptedSize
    println("Filename:\t" + metadata.filename)
    println("Encrypted size:\t" + metadata.encryptedSize + " bytes")
    println("Metadata version:\t" + metadata.metadataVersion)
    println("Metadata size:\t" + metadata.metadataSize + " bytes")
    println("IV:\t" + metadata.iv.mkString(""))
    println("Salt:\t" + metadata.salt.mkString(""))

    val derivedKey = deriveKeyFrom(passwordField.text.value.toCharArray(), metadata.salt)
    val key = new SecretKeySpec(derivedKey.key, "AES");
    val iv = new IvParameterSpec(metadata.iv);
    val properties = new Properties()
    val transform = "AES/CBC/PKCS5Padding"

    val fileInputStream = new FileInputStream(files(0))
    val cutoffInputStream = new CutoffInputStream(fileInputStream, metadata.encryptedSize)
    val cryptoInputStream = new CryptoInputStream(transform, properties, cutoffInputStream, key, iv)
    val fileOutputStream = new FileOutputStream(new File(files(0).getAbsolutePath + ".dec"))
    val data = ByteBuffer.allocate(1024).array()
    var totalBytesRead = 0
    var currentBytesRead = 0
    while (currentBytesRead > -1) {
      currentBytesRead = cryptoInputStream.read(data)
      if (currentBytesRead > -1) {
        totalBytesRead += currentBytesRead
        fileOutputStream.write(data, 0, currentBytesRead)
      }
      setProgress(totalBytes, totalBytesRead)
    }
    fileOutputStream.flush()
    fileOutputStream.close()
    cryptoInputStream.close()
    fileInputStream.close()
  }
  private def randomBytes(amount: Int): Array[Byte] = {
    val data = ArrayBuffer.fill(amount)(0.toByte).toArray
    CryptoRandomFactory.getCryptoRandom().nextBytes(data)
    return data
  }
  private def deriveKeyFrom(password: Array[Char], salt: Array[Byte]): DerivedKey = {
    val spec = new PBEKeySpec(password, salt, 65536, 128); // AES-128
    val secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
    return DerivedKey(secretKeyFactory.generateSecret(spec).getEncoded(), salt)
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
      val currentBytesRead = in.read(array, offset, (maxBytes - totalBytesRead).toInt)
      totalBytesRead += currentBytesRead
      return currentBytesRead
    } else { // reached the limit, so cut off
      return -1
    }
  }
}