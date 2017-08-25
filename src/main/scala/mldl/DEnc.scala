package mldl

import scalafx.application._
import scalafx.Includes._
import scalafx.scene._
import scalafx.scene.shape.Rectangle
import scalafx.scene.input.DragEvent
import scalafx.scene.paint._
import scalafx.animation.FadeTransition
import scalafx.animation.Interpolator
import scalafx.util.Duration
import scalafx.animation.FillTransition
import scalafx.scene.input.TransferMode
import scalafx.scene.layout.StackPane
import scalafx.scene.text.Text
import scalafx.scene.control.ProgressBar
import scalafx.scene.layout.BorderPane
import java.io.File
import java.util.Properties
import java.io.FileOutputStream
import java.io.ByteArrayOutputStream
import java.io.FileInputStream
import javax.crypto.spec.IvParameterSpec
import java.nio.charset.Charset
import javax.crypto.spec.SecretKeySpec
import org.apache.commons.crypto.stream.CryptoOutputStream
import java.nio.charset.StandardCharsets
import scala.collection.mutable.ArrayBuffer
import org.apache.commons.crypto.stream.CryptoInputStream
import scalafx.scene.control.PasswordField
import org.apache.commons.crypto.random.CryptoRandomFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.SecretKeyFactory
import java.io.PrintWriter
import java.io.RandomAccessFile
import java.nio.channels.FileChannel
import java.nio.file.Paths
import java.nio.file.StandardOpenOption
import java.nio.ByteBuffer
import java.io.FilterInputStream
import java.io.InputStream

object DEnc extends JFXApp {
  private case class DerivedKey(key: Array[Byte], salt: Array[Byte])
  private case class MetaData(
    filename: String,
    iv: Array[Byte],
    salt: Array[Byte],
    filesize: Long, // FIXME this could be a security issue
    encryptedSize: Long,
    metadataSize: Int)
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
    val meta = MetaData(files(0).getName, plainIv, salt, totalBytes, -1, -1)
    println("IV:\t" + meta.iv.mkString(""))
    println("Salt:\t" + meta.salt.mkString(""))
    val metaBytes = writeMetaData(meta, encryptedFile)
    println("wrote additional " + metaBytes + " bytes of metadata")
  }
  def decrypt(files: Seq[File]) = {
    val totalBytes = files(0).length()
    println("decrypting " + files(0) + " (" + totalBytes + " bytes) ...")

    val metadata = readMetadata(files(0))
    println("Filename:\t" + metadata.filename)
    println("File size:\t" + metadata.filesize + " bytes")
    println("Encrypted size:\t" + metadata.encryptedSize + " bytes")
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
  private def writeMetaData(metaData: MetaData, file: File): Long = {
    val encryptedSize = file.length()
    val fileOutputStream = new FileOutputStream(file, true)
    val filnameBytes = metaData.filename.getBytes(StandardCharsets.UTF_8)
    fileOutputStream.write(ByteBuffer.allocate(4).putInt(filnameBytes.length).array())
    fileOutputStream.write(filnameBytes)
    fileOutputStream.write(ByteBuffer.allocate(4).putInt(metaData.iv.length).array())
    fileOutputStream.write(metaData.iv)
    fileOutputStream.write(ByteBuffer.allocate(4).putInt(metaData.salt.length).array())
    fileOutputStream.write(metaData.salt)
    fileOutputStream.write(ByteBuffer.allocate(8).putLong(metaData.filesize).array())
    fileOutputStream.write(ByteBuffer.allocate(8).putLong(encryptedSize).array())
    val metadataSize = filnameBytes.length + metaData.iv.length + metaData.salt.length + 8 * 4
    fileOutputStream.write(ByteBuffer.allocate(4).putInt(metadataSize).array())
    fileOutputStream.flush()
    fileOutputStream.close()
    return metadataSize
  }
  private def readMetadata(file: File): MetaData = {
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
    val dataFilesize = ByteBuffer.allocate(8)
    fileChannel.read(dataFilesize)
    val dataEncryptedFilesize = ByteBuffer.allocate(8)
    fileChannel.read(dataEncryptedFilesize)
    return MetaData(
      new String(dataFileName.array(), StandardCharsets.UTF_8),
      dataIv.array(),
      dataSalt.array(),
      dataFilesize.getLong(0),
      dataEncryptedFilesize.getLong(0),
      dataMetaDataLength.getInt(0))
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
      if (totalBytesRead + length <= maxBytes) { // all fits in total maximum
        val currentBytesRead = in.read(array, offset, length) // TODO not tested
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