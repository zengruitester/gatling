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

package io.gatling.http.config

import io.gatling.BaseSpec
import io.gatling.commons.util.DefaultClock
import io.gatling.core.CoreComponents
import io.gatling.http.cache.HttpCaches
import io.gatling.core.config.GatlingConfiguration
import io.gatling.http.engine.HttpEngine
import io.gatling.http.protocol.{ HttpProtocol, HttpProtocolBuilder }

import org.mockito.Mockito.when

class HttpProtocolBuilderSpec extends BaseSpec {

  private val configuration = GatlingConfiguration.loadForTest()
  private val coreComponents = CoreComponents(null, null, null, null, new DefaultClock, null, configuration)
  private val httpCaches = new HttpCaches(coreComponents)
  private val httpEngine = mock[HttpEngine]
  private val httpProtocolBuilder = HttpProtocolBuilder(configuration)

  "http protocol configuration builder" should "set a silent URI regex" in {
    val builder = httpProtocolBuilder
      .silentUri(".*")

    val config: HttpProtocol = builder.build

    val actualPattern: String = config.requestPart.silentUri.get.toString
    actualPattern.equals(".*") shouldBe true
  }
}
