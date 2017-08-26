import com.github.retronym.SbtOneJar._

version := "0.2"

scalaVersion := "2.12.2"

oneJarSettings

libraryDependencies += "org.scalafx" %% "scalafx" % "8.0.102-R11"

// problem with CSS stylesheet resource loading
// see https://groups.google.com/forum/#!topic/scalafx-users/MzHb19SISHQ
//unmanagedJars in Compile += Attributed.blank(file(System.getenv("JAVA_HOME") + "/jre/lib/ext/jfxrt.jar"))

libraryDependencies += "org.apache.commons" % "commons-crypto" % "1.0.0"

jfxSettings

JFX.mainClass := Some("denc.DEnc")
