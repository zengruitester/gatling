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

package io.gatling.core.check.css

import io.gatling.core.check.{ Extractor, _ }
import io.gatling.core.session._

import jodd.lagarto.dom.NodeSelector

trait CssCheckType

trait CssOfType { self: CssCheckBuilder[String] =>

  def ofType[X: NodeConverter]: CssCheckBuilder[X] = new CssCheckBuilder[X](expression, nodeAttribute, selectors)
}

object CssCheckBuilder {

  def css(expression: Expression[String], nodeAttribute: Option[String], selectors: CssSelectors): CssCheckBuilder[String] with CssOfType =
    new CssCheckBuilder[String](expression, nodeAttribute, selectors) with CssOfType
}

class CssCheckBuilder[X: NodeConverter](
    private[css] val expression: Expression[String],
    private[css] val nodeAttribute: Option[String],
    private[css] val selectors: CssSelectors
) extends DefaultMultipleFindCheckBuilder[CssCheckType, NodeSelector, X](displayActualValue = true) {

  override def findExtractor(occurrence: Int): Expression[Extractor[NodeSelector, X]] =
    expression.map(new CssFindExtractor(_, nodeAttribute, occurrence, selectors))
  override def findAllExtractor: Expression[Extractor[NodeSelector, Seq[X]]] = expression.map(new CssFindAllExtractor(_, nodeAttribute, selectors))
  override def countExtractor: Expression[Extractor[NodeSelector, Int]] = expression.map(new CssCountExtractor(_, nodeAttribute, selectors))
}
