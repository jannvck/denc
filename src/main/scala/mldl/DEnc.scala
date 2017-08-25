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

object DEnc extends JFXApp {
  private case class DerivedKey(key: Array[Byte], salt: Array[Byte])
  private case class MetaData(filename: String, iv: Array[Byte], salt: Array[Byte])
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
    def genIV: Array[Byte] = {
      //Math.random().toString()
      var iv = ArrayBuffer.fill(1024)(0.toByte).toArray
      CryptoRandomFactory.getCryptoRandom
      iv
    }
    val totalBytes = files(0).length()
    println("encrypting " + files(0) + " (" + totalBytes + " bytes) ...")
    
    val salt = randomBytes(16)
    val derivedKey = deriveKeyFrom(passwordField.text.value.toCharArray(), salt)
    val key = new SecretKeySpec(derivedKey.key, "AES");
    val iv = new IvParameterSpec("1234567890123456".getBytes(StandardCharsets.UTF_8));
    val properties = new Properties()
    val transform = "AES/CBC/PKCS5Padding"

    val fileOutputStream = new FileOutputStream(new File(files(0).getAbsolutePath + ".enc"))
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
  }
  def decrypt(files: Seq[File]) = {
    val totalBytes = files(0).length()
    println("decrypting " + files(0) + " (" + totalBytes + " bytes) ...")
    
    val derivedKey = deriveKeyFrom(passwordField.text.value.toCharArray(), null)
    val key = new SecretKeySpec(derivedKey.key, "AES");
    val iv = new IvParameterSpec("1234567890123456".getBytes(StandardCharsets.UTF_8));
    val properties = new Properties()
    val transform = "AES/CBC/PKCS5Padding"

    val fileInputStream = new FileInputStream(files(0))
    val cryptoInputStream = new CryptoInputStream(transform, properties, fileInputStream, key, iv)
    val fileOutputStream = new FileOutputStream(new File(files(0).getAbsolutePath + ".dec"))
    val data = ArrayBuffer.fill(1024)(0.toByte).toArray
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
  private def addMetaData(metaData: MetaData, file: File) = {
    
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