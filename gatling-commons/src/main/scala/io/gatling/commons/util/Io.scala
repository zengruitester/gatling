/*
 * Copyright 2011-2019 GatlingCorp (https://gatling.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.gatling.commons.util

import java.io._
import java.net.{ URISyntaxException, URL }
import java.nio.charset.Charset
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.{ FileVisitResult, Files, Path, SimpleFileVisitor }

import scala.io.Source
import scala.util.control.NonFatal

object Io {

  val DefaultBufferSize: Int = 8 * 1024

  implicit class RichURL(val url: URL) extends AnyVal {

    def file: File =
      try {
        new File(url.toURI)
      } catch {
        case _: URISyntaxException => new File(url.getPath)
      }
  }

  implicit class RichInputStream(val is: InputStream) extends AnyVal {

    @SuppressWarnings(Array("org.wartremover.warts.DefaultArguments"))
    def toString(charset: Charset, bufferSize: Int = DefaultBufferSize): String = {
      val writer = new FastStringWriter(bufferSize)
      val reader = new InputStreamReader(is, charset)

      reader.copyTo(writer, bufferSize)

      writer.toString
    }

    def toByteArray(): Array[Byte] = {
      val os = FastByteArrayOutputStream.pooled()
      os.write(is)
      os.toByteArray
    }

    @SuppressWarnings(Array("org.wartremover.warts.DefaultArguments"))
    def copyTo(os: OutputStream, bufferSize: Int = DefaultBufferSize): Int = {

      def copyLarge(buffer: Array[Byte]): Long = {

        var lastReadCount: Int = 0
        def read(): Int = {
          lastReadCount = is.read(buffer)
          lastReadCount
        }

        var count: Long = 0

        while (read() != -1) {
          os.write(buffer, 0, lastReadCount)
          count += lastReadCount
        }

        count
      }

      copyLarge(new Array[Byte](bufferSize)) match {
        case l if l > Integer.MAX_VALUE => -1
        case l                          => l.toInt
      }
    }
  }

  implicit class RichReader(val reader: Reader) extends AnyVal {

    @SuppressWarnings(Array("org.wartremover.warts.DefaultArguments"))
    def copyTo(writer: Writer, bufferSize: Int = DefaultBufferSize): Int = {

      def copyLarge(buffer: Array[Char]) = {

        var lastReadCount: Int = 0
        def read(): Int = {
          lastReadCount = reader.read(buffer)
          lastReadCount
        }

        var count: Long = 0

        while (read() != -1) {
          writer.write(buffer, 0, lastReadCount)
          count += lastReadCount
        }

        count
      }

      copyLarge(new Array[Char](bufferSize)) match {
        case l if l > Integer.MAX_VALUE => -1
        case l                          => l.toInt
      }
    }
  }

  def withCloseable[T, C <: AutoCloseable](closeable: C)(block: C => T): T =
    try block(closeable)
    finally closeable.close()

  def withSource[T, C <: Source](closeable: C)(block: C => T): T =
    try block(closeable)
    finally closeable.close()

  def deleteDirectoryAsap(directory: Path): Unit =
    if (!deleteDirectory(directory)) {
      deleteDirectoryOnExit(directory)
    }

  /**
   * Delete a possibly non empty directory
   *
   * @param directory the directory to delete
   * @return if directory could be deleted
   */
  def deleteDirectory(directory: Path): Boolean =
    try {
      Files.walkFileTree(
        directory,
        new SimpleFileVisitor[Path]() {
          @throws[IOException]
          override def visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult = {
            Files.delete(file)
            FileVisitResult.CONTINUE
          }

          @throws[IOException]
          override def postVisitDirectory(dir: Path, exc: IOException): FileVisitResult = {
            Files.delete(dir)
            FileVisitResult.CONTINUE
          }
        }
      )
      true
    } catch {
      case NonFatal(_) => false
    }

  /**
   * Make a possibly non empty directory to be deleted on exit
   *
   * @param directory the directory to delete
   */
  def deleteDirectoryOnExit(directory: Path): Unit =
    Files.walkFileTree(
      directory,
      new SimpleFileVisitor[Path]() {
        @throws[IOException]
        override def visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult = {
          file.toFile.deleteOnExit()
          FileVisitResult.CONTINUE
        }

        @throws[IOException]
        override def postVisitDirectory(dir: Path, exc: IOException): FileVisitResult = {
          dir.toFile.deleteOnExit()
          FileVisitResult.CONTINUE
        }
      }
    )
}
