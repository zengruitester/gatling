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

import io.gatling.core.CoreDsl
import io.gatling.core.check.CheckResult
import io.gatling.core.check.jsonpath.JsonPathCheckType
import io.gatling.core.config.GatlingConfiguration
import io.gatling.core.json.JsonParsers
import io.gatling.core.session._
import io.gatling.http.HttpDsl
import io.gatling.http.check.HttpCheckMaterializer
import io.gatling.http.response.{ Response, StringResponseBody }
import io.gatling.{ BaseSpec, ValidationValues }

import com.fasterxml.jackson.databind.JsonNode
import io.netty.handler.codec.http.{ DefaultHttpHeaders, HttpResponseStatus }

class HttpBodyJsonpJsonPathCheckSpec extends BaseSpec with ValidationValues with CoreDsl with HttpDsl {

  implicit val configuration: GatlingConfiguration = GatlingConfiguration.loadForTest()
  implicit val materializer: HttpCheckMaterializer[JsonPathCheckType, JsonNode] = new HttpBodyJsonPathCheckMaterializer(JsonParsers())

  private val session = Session("mockSession", 0, System.currentTimeMillis())

  private def mockResponse(body: String): Response =
    Response(
      request = null,
      wireRequestHeaders = new DefaultHttpHeaders,
      status = HttpResponseStatus.OK,
      headers = new DefaultHttpHeaders,
      body = new StringResponseBody(body, UTF_8),
      checksums = null,
      bodyLength = 0,
      charset = UTF_8,
      startTimestamp = 0,
      endTimestamp = 0,
      isHttp2 = false
    )

  private val storeJson = """someJsMethod({ "store": {
                            |    "book": "In store"
                            |  },
                            |  "street": {
                            |    "book": "On the street"
                            |  }
                            |});""".stripMargin.replaceAll("""[\r\n]""", "")

  "jsonpJsonPath.find.exists" should "find single result into JSON serialized form" in {
    val response = mockResponse(storeJson)
    jsonpJsonPath("$.street").find.exists.check(response, session, new JHashMap[Any, Any]).succeeded shouldBe CheckResult(
      Some("""{"book":"On the street"}"""),
      None
    )
  }
}
