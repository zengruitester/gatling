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

package io.gatling.core.action

import scala.util.control.NonFatal

import io.gatling.commons.util.Clock
import io.gatling.commons.util.Throwables._
import io.gatling.commons.validation.Validation
import io.gatling.core.session.{ Expression, Session }
import io.gatling.core.stats.StatsEngine

import akka.actor.ActorRef
import com.typesafe.scalalogging.StrictLogging

/**
 * Top level abstraction in charge of executing concrete actions along a scenario, for example sending an HTTP request.
 */
trait Action extends StrictLogging {

  def name: String

  def !(session: Session): Unit = execute(session)

  /**
   * Core method executed when the Action received a Session message
   *
   * @param session the session of the virtual user
   * @return Nothing
   */
  def execute(session: Session): Unit
}

/**
 * An Action that is to be chained with another.
 * Almost all Gatling Actions are Chainable.
 * For example, the final Action at the end of a scenario workflow is not.
 */
trait ChainableAction extends Action {

  /**
   * @return the next Action in the scenario workflow
   */
  def next: Action

  override abstract def !(session: Session): Unit =
    try {
      super.!(session)
    } catch {
      case reason: IllegalStateException if reason.getMessage == "cannot enqueue after timer shutdown" =>
        logger.debug(s"'$name' crashed with '${reason.detailedMessage}', ignoring")
      case NonFatal(reason) =>
        if (logger.underlying.isInfoEnabled)
          logger.error(s"'$name' crashed on session $session, forwarding to the next one", reason)
        else
          logger.error(s"'$name' crashed with '${reason.detailedMessage}', forwarding to the next one")
        next.execute(session.markAsFailed)
    }

  def recover(session: Session)(v: Validation[_]): Unit =
    v.onFailure { message =>
      logger.error(s"'$name' failed to execute: $message")
      next ! session.markAsFailed
    }
}

class ActorDelegatingAction(val name: String, actor: ActorRef) extends Action {

  def execute(session: Session): Unit = actor ! session
}

class ExitableActorDelegatingAction(name: String, val statsEngine: StatsEngine, val clock: Clock, val next: Action, actor: ActorRef)
    extends ActorDelegatingAction(name, actor)
    with ExitableAction

trait RequestAction extends ExitableAction {

  def requestName: Expression[String]
  def sendRequest(requestName: String, session: Session): Validation[Unit]

  override def execute(session: Session): Unit = recover(session) {
    requestName(session).flatMap { resolvedRequestName =>
      val outcome =
        try {
          sendRequest(resolvedRequestName, session)
        } catch {
          case NonFatal(e) =>
            statsEngine.reportUnbuildableRequest(session, resolvedRequestName, e.detailedMessage)
            // rethrow so we trigger exception handling in "!"
            throw e
        }
      outcome.onFailure { errorMessage =>
        statsEngine.reportUnbuildableRequest(session, resolvedRequestName, errorMessage)
      }
      outcome
    }
  }
}

trait ActorBasedAction {

  // import optimized TypeCaster
  import io.gatling.core.util.CoreTypeCaster._

  def actorFetchErrorMessage: String

  final def fetchActor(actorName: String, session: Session): Validation[ActorRef] =
    session(actorName)
      .validate[ActorRef]
      .mapError(m => s"$actorFetchErrorMessage: $m")
}
