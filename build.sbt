import com.github.retronym.SbtOneJar._

version := "0.3"

scalaVersion := "2.12.2"

oneJarSettings

libraryDependencies += "org.scalafx" %% "scalafx" % "8.0.102-R11"

libraryDependencies += "org.apache.commons" % "commons-crypto" % "1.0.0"

jfxSettings

JFX.mainClass := Some("denc.DEnc")
