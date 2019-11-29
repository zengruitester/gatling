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

package io.gatling.http.check.header

import io.gatling.core.check._
import io.gatling.core.check.regex.{ GroupExtractor, Patterns }
import io.gatling.core.session.Expression
import io.gatling.http.check.HttpCheckMaterializer
import io.gatling.http.check.HttpCheckScope.Header
import io.gatling.http.response.Response

trait HttpHeaderRegexCheckType

trait HttpHeaderRegexOfType {
  self: HttpHeaderRegexCheckBuilder[String] =>

  def ofType[X: GroupExtractor]: HttpHeaderRegexCheckBuilder[X] = new HttpHeaderRegexCheckBuilder[X](headerName, pattern, patterns)
}

object HttpHeaderRegexCheckBuilder {

  def headerRegex(
      headerName: Expression[String],
      pattern: Expression[String],
      patterns: Patterns
  ): HttpHeaderRegexCheckBuilder[String] with HttpHeaderRegexOfType =
    new HttpHeaderRegexCheckBuilder[String](headerName, pattern, patterns) with HttpHeaderRegexOfType
}

class HttpHeaderRegexCheckBuilder[X: GroupExtractor](
    private[header] val headerName: Expression[String],
    private[header] val pattern: Expression[String],
    private[header] val patterns: Patterns
) extends DefaultMultipleFindCheckBuilder[HttpHeaderRegexCheckType, Response, X](displayActualValue = true) {

  private def withHeaderAndPattern[T](f: (String, String) => T): Expression[T] =
    session =>
      for {
        headerName <- headerName(session)
        pattern <- pattern(session)
      } yield f(headerName, pattern)

  override def findExtractor(occurrence: Int): Expression[Extractor[Response, X]] =
    withHeaderAndPattern(new HttpHeaderRegexFindExtractor(_, _, occurrence, patterns))

  override def findAllExtractor: Expression[Extractor[Response, Seq[X]]] = withHeaderAndPattern(new HttpHeaderRegexFindAllExtractor(_, _, patterns))

  override def countExtractor: Expression[Extractor[Response, Int]] = withHeaderAndPattern(new HttpHeaderRegexCountExtractor(_, _, patterns))
}

object HttpHeaderRegexCheckMaterializer extends HttpCheckMaterializer[HttpHeaderRegexCheckType, Response](Header) {

  override val preparer: Preparer[Response, Response] = identityPreparer
}
