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

package io.gatling.http.feeder

import java.io.{ IOException, InputStream }
import java.nio.file.Paths

import io.gatling.{ BaseSpec, ValidationValues }
import io.gatling.commons.util.Io._
import io.gatling.core.util.Resource
import io.gatling.core.feeder.Record

import org.mockito.Mockito._
import org.mockito.ArgumentMatchers._

class SitemapParserSpec extends BaseSpec with ValidationValues {

  private def getIs(filePath: String) = getClass.getClassLoader.getResourceAsStream(filePath)

  "sitemap parser" should "parse valid sitemap input stream" in {
    withCloseable(getIs("sitemap.xml")) { is =>
      val records = SitemapParser.parse(is).toArray
      verifySitemapRecords(records)
    }
  }

  it should "parse valid sitemap file" in {
    val resource = Resource.resolveResource(Paths.get(""), "sitemap.xml")
    val records = resource.map(SitemapParser.parse(_).toArray)
    verifySitemapRecords(records.succeeded)
  }

  it should "input stream is closed on error" in {
    val fileIs = mock[InputStream]
    val resource = mock[Resource]
    when(resource.inputStream).thenReturn(fileIs)
    when(fileIs.read()) thenThrow new IOException
    when(fileIs.read(any[Array[Byte]])) thenThrow new IOException
    when(fileIs.read(any[Array[Byte]], anyInt, anyInt)) thenThrow new IOException

    a[IOException] shouldBe thrownBy(SitemapParser.parse(resource).toArray)
  }

  it should "throw exception when loc node is missing" in {
    a[SitemapFormatException] shouldBe thrownBy(SitemapParser.parse(getIs("sitemap_loc_missing.xml")))
  }

  it should "throw exception when loc node has no value" in {
    a[SitemapFormatException] shouldBe thrownBy(SitemapParser.parse(getIs("sitemap_no_value.xml")))
  }

  private def verifySitemapRecords(records: Array[Record[String]]) = {
    records should have size 5

    records(0) shouldBe Map(
      "loc" -> "http://www.example.com/",
      "lastmod" -> "2005-01-01",
      "changefreq" -> "monthly",
      "priority" -> "0.8"
    )

    records(1) shouldBe Map(
      "loc" -> "http://www.example.com/catalog?item=12&amp;desc=vacation_hawaii",
      "changefreq" -> "weekly"
    )

    records(2) shouldBe Map(
      "loc" -> "http://www.example.com/catalog?item=73&amp;desc=vacation_new_zealand",
      "lastmod" -> "2004-12-23",
      "changefreq" -> "weekly"
    )

    records(3) shouldBe Map(
      "loc" -> "http://www.example.com/catalog?item=74&amp;desc=vacation_newfoundland",
      "lastmod" -> "2004-12-23T18:00:15+00:00",
      "priority" -> "0.3"
    )

    records(4) shouldBe Map(
      "loc" -> "http://www.example.com/catalog?item=83&amp;desc=vacation_usa",
      "lastmod" -> "2004-11-23"
    )
  }
}
