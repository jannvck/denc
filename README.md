# denc
Small multiplatform tool with a GUI to encrypt/decrypt files. Written in Scala and implemented as a JavaFX application using [ScalaFX](http://www.scalafx.org/) and [Apache Commons Crypto](https://commons.apache.org/proper/commons-crypto/).

![Screenshot](https://raw.githubusercontent.com/jannvck/denc/master/release/denc-0.3-screenshot.png)

## Download
Please find a link to the latest release below:

* [Download denc 0.3](https://raw.githubusercontent.com/jannvck/denc/master/release/denc-0.3.jar)

## Building
First clone or download this repository. Then also download and install [sbt](http://www.scala-sbt.org/). Finally run the following command in the main directory:
```
sbt assembly
```
This will produce an executable *denc-assembly-0.3.jar* file in the *target/scala-2.12* directory.

## Usage instructions
To encrypt or decrypt files just drag them into the corresponding fields in the graphical user interface.
The interface also contains a field at the top to insert a password.
