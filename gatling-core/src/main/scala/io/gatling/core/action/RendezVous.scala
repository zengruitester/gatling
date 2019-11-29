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

import scala.collection.mutable

import io.gatling.commons.util.Clock
import io.gatling.core.session.Session
import io.gatling.core.stats.StatsEngine
import io.gatling.core.util.NameGen
import io.gatling.core.akka.BaseActor

import akka.actor.{ ActorSystem, Props }

object RendezVous extends NameGen {

  def apply(users: Int, actorSystem: ActorSystem, statsEngine: StatsEngine, clock: Clock, next: Action): Action = {
    val actor = actorSystem.actorOf(RendezVousActor.props(users, next))
    new ExitableActorDelegatingAction(genName("rendezVous"), statsEngine, clock, next, actor)
  }
}

object RendezVousActor {
  def props(users: Int, next: Action): Props =
    Props(new RendezVousActor(users: Int, next))
}

/**
 * Buffer Sessions until users is reached, then unleash buffer and become passthrough.
 */
class RendezVousActor(users: Int, val next: Action) extends BaseActor {

  private val buffer = mutable.Queue.empty[Session]

  private val passThrough: Receive = {
    case session: Session => next ! session
  }

  def execute(session: Session): Unit = {
    buffer += session
    if (buffer.length == users) {
      context.become(passThrough)
      buffer.foreach(next ! _)
      buffer.clear()
    }
  }

  override def receive: Receive = {
    case session: Session => execute(session)
  }

  /**
   * Makes sure that in case of an actor crash, the Session is not lost but passed to the next Action.
   */
  override def preRestart(reason: Throwable, message: Option[Any]): Unit =
    message.foreach {
      case session: Session =>
        logger.error(s"'${self.path.name}' crashed on session $session, forwarding to the next one", reason)
        next.execute(session.markAsFailed)
      case _ =>
        logger.error(s"'${self.path.name}' crashed on unknown message $message, dropping", reason)
    }
}
