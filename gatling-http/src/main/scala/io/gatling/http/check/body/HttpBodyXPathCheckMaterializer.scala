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

import io.gatling.commons.validation._
import io.gatling.core.check.Preparer
import io.gatling.core.check.xpath.{ Dom, XPathCheckType, XmlParsers }
import io.gatling.http.check.HttpCheckMaterializer
import io.gatling.http.check.HttpCheckScope.Body
import io.gatling.http.response.Response

import org.xml.sax.InputSource

class HttpBodyXPathCheckMaterializer(xmlParsers: XmlParsers) extends HttpCheckMaterializer[XPathCheckType, Option[Dom]](Body) {

  private val ErrorMapper: String => String = "Could not parse response into a DOM Document: " + _

  private def xpathPreparer[T](f: InputSource => T)(response: Response): Validation[Option[T]] =
    safely(ErrorMapper) {
      val root =
        if (response.hasResponseBody) {
          val inputSource = new InputSource(response.body.stream)
          inputSource.setEncoding(response.charset.name)
          Some(f(inputSource))

        } else {
          None
        }
      root.success
    }

  override val preparer: Preparer[Response, Option[Dom]] =
    xpathPreparer(xmlParsers.parse)
}
