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

import jodd.lagarto.LagartoParser
import jodd.lagarto.dom.{ LagartoDOMBuilder, LagartoDomBuilderConfig }
import jodd.log.LoggerFactory
import jodd.log.impl.Slf4jLogger

object Jodd {

  LoggerFactory.setLoggerProvider(Slf4jLogger.PROVIDER)

  private val IeVersionDroppingCc = 10.0

  private def joddConfigBase =
    new LagartoDomBuilderConfig()
      .setParsingErrorLogLevelName("INFO")
      .setCaseSensitive(false)

  private val JoddConfig = joddConfigBase
    .setEnableConditionalComments(false)

  def getJoddConfig(ieVersion: Option[Float]): LagartoDomBuilderConfig =
    ieVersion match {
      case Some(version) if version < IeVersionDroppingCc =>
        joddConfigBase
          .setEnableConditionalComments(true)
          .setCondCommentIEVersion(version)

      case _ => JoddConfig
    }

  def newLagartoDomBuilder: LagartoDOMBuilder = {
    val domBuilder = new LagartoDOMBuilder
    domBuilder.setConfig(JoddConfig)
    domBuilder
  }

  def newLagartoParser(chars: Array[Char], ieVersion: Option[Float]): LagartoParser = {
    val lagartoParser = new LagartoParser(chars)
    lagartoParser.setConfig(getJoddConfig(ieVersion))
    lagartoParser
  }
}
