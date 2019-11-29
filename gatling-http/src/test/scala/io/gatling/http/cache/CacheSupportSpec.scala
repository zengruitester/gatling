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

package io.gatling.http.cache

import java.nio.charset.StandardCharsets.UTF_8

import io.gatling.BaseSpec
import io.gatling.commons.util.DefaultClock
import io.gatling.core.CoreComponents
import io.gatling.core.session.Session
import io.gatling.core.config.GatlingConfiguration
import io.gatling.http.client.uri.Uri
import io.gatling.http.client.{ Request, RequestBuilder }
import io.gatling.http.engine.HttpEngine
import io.gatling.http.engine.tx.HttpTx
import io.gatling.http.protocol.HttpProtocol
import io.gatling.http.request.{ HttpRequest, HttpRequestConfig }
import io.gatling.http.{ HeaderNames, HeaderValues }
import io.gatling.http.response.{ Response, ResponseBody }

import io.netty.handler.codec.http.{ DefaultHttpHeaders, EmptyHttpHeaders, HttpMethod, HttpResponseStatus }
import org.mockito.ArgumentMatchers.any
import org.mockito.Mockito.when

class CacheSupportSpec extends BaseSpec {

  // Default config
  private val configuration = GatlingConfiguration.loadForTest()
  private val clock = new DefaultClock
  private val coreComponents = CoreComponents(null, null, null, null, new DefaultClock, null, configuration)
  private val httpCaches = new HttpCaches(coreComponents)

  class CacheContext {

    private val request = new RequestBuilder(HttpMethod.GET, Uri.create("http://localhost"))
      .build()

    def getResponseExpire(headers: Seq[(String, String)]): Option[Long] = {
      val status = mock[HttpResponseStatus]
      val body = mock[ResponseBody]
      val headersMap = new DefaultHttpHeaders
      headers.foreach { case (headerName, headerValue) => headersMap.add(headerName, headerValue) }
      val response = Response(request, EmptyHttpHeaders.INSTANCE, status, headersMap, body, Map.empty, 0, UTF_8, -1, -1, isHttp2 = false)

      httpCaches.getResponseExpires(response)
    }
  }

  "getResponseExpires()" should "correctly support Pragma header" in new CacheContext {
    getResponseExpire(List(HeaderNames.Pragma -> HeaderValues.NoCache)) shouldBe None
  }

  it should "correctly support Cache-Control header" in new CacheContext {
    getResponseExpire(List(HeaderNames.CacheControl -> "max-age=1")) shouldBe 'defined
    getResponseExpire(List(HeaderNames.CacheControl -> "private, max-age=3600, must-revalidate")) shouldBe 'defined
    getResponseExpire(List(HeaderNames.CacheControl -> "public, no-cache")) shouldBe None
    getResponseExpire(List(HeaderNames.CacheControl -> "public, max-age=-1")) shouldBe None
    getResponseExpire(List(HeaderNames.CacheControl -> "public, max-age=0")) shouldBe None
    getResponseExpire(List(HeaderNames.CacheControl -> HeaderValues.NoStore)) shouldBe None
  }

  it should "correctly support Expires header" in new CacheContext {
    getResponseExpire(List(HeaderNames.Expires -> "Sun, 16 Oct 2033 21:56:44 GMT")) shouldBe 'defined
  }

  it should "give priority to Cache-Control over Expires" in new CacheContext {
    getResponseExpire(List(HeaderNames.Expires -> "Tue, 19 Jan 2038 03:14:06 GMT", HeaderNames.CacheControl -> HeaderValues.NoStore)) shouldBe None
    getResponseExpire(List(HeaderNames.Expires -> "Tue, 19 Jan 2038 03:14:06 GMT", HeaderNames.CacheControl -> "max-age=-1")) shouldBe None
    getResponseExpire(List(HeaderNames.Expires -> "Tue, 19 Jan 2038 03:14:06 GMT", HeaderNames.CacheControl -> "max-age=0")) shouldBe None
    getResponseExpire(List(HeaderNames.Expires -> "Tue, 19 Jan 2038 03:14:06 GMT", HeaderNames.CacheControl -> "max-age=567")) shouldBe 'defined
  }

  it should "Pragma has priority over Cache-Control" in new CacheContext {
    getResponseExpire(List(HeaderNames.Pragma -> HeaderValues.NoCache, HeaderNames.CacheControl -> "max-age=3600")) shouldBe None
    getResponseExpire(List(HeaderNames.Pragma -> HeaderValues.NoCache, HeaderNames.Expires -> "3600")) shouldBe None
  }

  "extractExpiresValue()" should "supports Expires field format" in {
    httpCaches.extractExpiresValue("Thu, 01 Dec 1994 16:00:00 GMT") shouldBe Some(786297600000L)
    httpCaches.extractExpiresValue("Tue, 19 Jan 2038 03:14:06 GMT") shouldBe Some(2147483646000L)
  }

  it should "defaults to false if it's not Expires field format" in {
    httpCaches.extractExpiresValue("fail") shouldBe None
  }

  "extractMaxAgeValue()" should "tell if there is a 'max-age' control and gets its value if superior to zero" in {
    httpCaches.extractMaxAgeValue("public") shouldBe None
    httpCaches.extractMaxAgeValue("private, max-age=3600, must-revalidate") shouldBe Some(3600)
    httpCaches.extractMaxAgeValue("private, max-age=nicolas, must-revalidate") shouldBe None
    httpCaches.extractMaxAgeValue("private, max-age=0, must-revalidate") shouldBe Some(0)
    httpCaches.extractMaxAgeValue("max-age=-1") shouldBe Some(-1)
    httpCaches.extractMaxAgeValue("max-age=-123") shouldBe Some(-1)
    httpCaches.extractMaxAgeValue("max-age=5") shouldBe Some(5)
    httpCaches.extractMaxAgeValue("max-age=567") shouldBe Some(567)
  }

  class RedirectContext {
    var session: Session = Session("mockSession", 0, clock.nowMillis)

    def addRedirect(from: String, to: String): Unit = {
      val request = new RequestBuilder(HttpMethod.GET, Uri.create(from))
        .build()
      session = httpCaches.addRedirect(session, request, Uri.create(to))
    }
  }

  "redirect memoization" should "return transaction with no redirect cache" in new RedirectContext {
    val tx = txTo("http://example.com/", session, redirectCount = 0, cache = true)
    val actualTx = httpCaches.applyPermanentRedirect(tx)

    actualTx shouldBe tx
  }

  it should "return updated transaction with single redirect" in new RedirectContext {
    addRedirect("http://example.com/", "http://gatling.io/")

    val origTx = txTo("http://example.com/", session, redirectCount = 0, cache = true)
    val tx = httpCaches.applyPermanentRedirect(origTx)

    tx.request.clientRequest.getUri shouldBe Uri.create("http://gatling.io/")
    tx.redirectCount shouldBe 1

  }

  it should "return updated transaction with several redirects" in new RedirectContext {
    addRedirect("http://example.com/", "http://gatling.io/")
    addRedirect("http://gatling.io/", "http://gatling2.io/")
    addRedirect("http://gatling2.io/", "http://gatling3.io/")

    val origTx = txTo("http://example.com/", session, redirectCount = 0, cache = true)
    val tx = httpCaches.applyPermanentRedirect(origTx)

    tx.request.clientRequest.getUri shouldBe Uri.create("http://gatling3.io/")
    tx.redirectCount shouldBe 3

  }

  it should "return updated transaction with several redirects, with redirectCount preset" in new RedirectContext {
    addRedirect("http://example.com/", "http://gatling.io/")
    addRedirect("http://gatling.io/", "http://gatling2.io/")
    addRedirect("http://gatling2.io/", "http://gatling3.io/")

    // Redirect count is already 2
    val origTx = txTo("http://example.com/", session, 2, cache = true)
    val tx = httpCaches.applyPermanentRedirect(origTx)

    tx.request.clientRequest.getUri shouldBe Uri.create("http://gatling3.io/")
    // After 3 more redirects it is now equal to 5
    tx.redirectCount shouldBe 5
  }

  private def txTo(uri: String, session: Session, redirectCount: Int, cache: Boolean) = {
    val protocol = HttpProtocol(configuration)
    val request = mock[Request]
    val caches = mock[HttpCaches]

    when(request.getUri) thenReturn Uri.create(uri)
    when(request.getHeaders) thenReturn new DefaultHttpHeaders
    when(caches.setNameResolver(any[HttpProtocol], any[HttpEngine])) thenReturn identity[Session] _

    HttpTx(
      session,
      request = HttpRequest(
        requestName = "mockHttpTx",
        clientRequest = request,
        requestConfig = HttpRequestConfig(
          checks = Nil,
          responseTransformer = None,
          maxRedirects = 10,
          throttled = false,
          silent = None,
          followRedirect = true,
          httpProtocol = protocol,
          explicitResources = Nil
        )
      ),
      responseBuilderFactory = null,
      next = null,
      resourceTx = None,
      redirectCount = redirectCount
    )
  }
}
