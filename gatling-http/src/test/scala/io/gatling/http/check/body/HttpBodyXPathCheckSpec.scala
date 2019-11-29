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

package io.gatling.http.check.body

import java.nio.charset.StandardCharsets._
import java.util.{ HashMap => JHashMap }

import scala.xml.Elem

import io.gatling.{ BaseSpec, ValidationValues }
import io.gatling.core.CoreDsl
import io.gatling.core.check.CheckResult
import io.gatling.core.check.xpath.{ Dom, XPathCheckType }
import io.gatling.core.config.GatlingConfiguration
import io.gatling.core.session._
import io.gatling.http.HttpDsl
import io.gatling.http.check.HttpCheckMaterializer
import io.gatling.http.response.{ Response, StringResponseBody }

import io.netty.handler.codec.http.{ DefaultHttpHeaders, HttpResponseStatus }

class HttpBodyXPathCheckSpec extends BaseSpec with ValidationValues with CoreDsl with HttpDsl {

  override implicit val configuration: GatlingConfiguration = GatlingConfiguration.loadForTest()
  private implicit val materializer: HttpCheckMaterializer[XPathCheckType, Option[Dom]] = new HttpBodyXPathCheckMaterializer(defaultXmlParsers)

  private val session = Session("mockSession", 0, System.currentTimeMillis())

  private def mockResponse(xml: Elem): Response = {
    val headers = new DefaultHttpHeaders().add(HttpHeaderNames.ContentType, s"${HttpHeaderValues.ApplicationXml}; charset=$UTF_8")
    val body = xml.toString()
    Response(
      request = null,
      wireRequestHeaders = headers,
      status = HttpResponseStatus.OK,
      headers = headers,
      body = new StringResponseBody(body, UTF_8),
      checksums = Map.empty,
      bodyLength = body.getBytes(UTF_8).length,
      charset = UTF_8,
      startTimestamp = 0,
      endTimestamp = 0,
      isHttp2 = false
    )
  }

  "xpath.find.exists" should "find single result" in {

    val response = mockResponse(<id>1072920417</id>)

    xpath("/id", Nil).find.exists.check(response, session, new JHashMap[Any, Any]).succeeded shouldBe CheckResult(Some("1072920417"), None)
  }

  it should "find first occurrence" in {

    val response = mockResponse(<root>
                                  <id>1072920417</id><id>1072920418</id>
                                </root>)

    xpath("//id").find.exists.check(response, session, new JHashMap[Any, Any]).succeeded shouldBe CheckResult(Some("1072920417"), None)
  }

  "xpath.findAll.exists" should "find all occurrences" in {

    val response = mockResponse(<root>
                                  <id>1072920417</id><id>1072920418</id>
                                </root>)

    xpath("//id").findAll.exists.check(response, session, new JHashMap[Any, Any]).succeeded shouldBe CheckResult(Some(Seq("1072920417", "1072920418")), None)
  }

  it should "fail when finding nothing instead of returning an empty Seq" in {

    val response = mockResponse(<root>
                                  <id>1072920417</id><id>1072920418</id>
                                </root>)

    xpath("//fo").findAll.exists.check(response, session, new JHashMap[Any, Any]).failed shouldBe "xpath((//fo,List())).findAll.exists, found nothing"
  }

  "xpath.count.exists" should "find all occurrences" in {

    val response = mockResponse(<root>
                                  <id>1072920417</id><id>1072920418</id>
                                </root>)

    xpath("//id").count.exists.check(response, session, new JHashMap[Any, Any]).succeeded shouldBe CheckResult(Some(2), None)
  }

  it should "return 0 when finding nothing instead of failing" in {

    val response = mockResponse(<root>
                                  <id>1072920417</id><id>1072920418</id>
                                </root>)

    xpath("//fo").count.exists.check(response, session, new JHashMap[Any, Any]).succeeded shouldBe CheckResult(Some(0), None)
  }
}
