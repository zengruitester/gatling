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

package io.gatling.core.stats

import java.util.concurrent.atomic.AtomicBoolean

import scala.concurrent.{ Await, ExecutionContext, Future }
import scala.concurrent.duration._

import io.gatling.commons.stats.Status
import io.gatling.commons.util.Clock
import io.gatling.core.config.GatlingConfiguration
import io.gatling.core.controller.ControllerCommand
import io.gatling.core.scenario.SimulationParams
import io.gatling.core.session.{ GroupBlock, Session }
import io.gatling.core.stats.writer._

import akka.actor.{ Actor, ActorRef, ActorSystem, Props }
import akka.pattern.ask
import akka.util.Timeout

trait StatsEngine {

  def start(): Unit

  def stop(replyTo: ActorRef, exception: Option[Exception]): Unit

  def logUserStart(session: Session): Unit

  def logUserEnd(userMessage: UserEndMessage): Unit

  // [fl]
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  // [fl]

  def logResponse(
      session: Session,
      requestName: String,
      startTimestamp: Long,
      endTimestamp: Long,
      status: Status,
      responseCode: Option[String],
      message: Option[String]
  ): Unit

  def logGroupEnd(
      session: Session,
      group: GroupBlock,
      exitTimestamp: Long
  ): Unit

  def logCrash(session: Session, requestName: String, error: String): Unit

  def reportUnbuildableRequest(session: Session, requestName: String, errorMessage: String): Unit =
    logCrash(session, requestName, s"Failed to build request: $errorMessage")
}

object DataWritersStatsEngine {

  def apply(
      simulationParams: SimulationParams,
      runMessage: RunMessage,
      system: ActorSystem,
      clock: Clock,
      configuration: GatlingConfiguration
  ): DataWritersStatsEngine = {

    val dataWriters = configuration.data.dataWriters.map { dw =>
      val clazz = Class.forName(dw.className).asInstanceOf[Class[Actor]]
      system.actorOf(Props(clazz, clock, configuration), clazz.getName)
    }

    val allPopulationBuilders = simulationParams.rootPopulationBuilders ++ simulationParams.childrenPopulationBuilders.values.flatten

    val dataWriterInitMessage = Init(
      simulationParams.assertions,
      runMessage,
      allPopulationBuilders.map(pb => ShortScenarioDescription(pb.scenarioBuilder.name, pb.injectionProfile.totalUserCount))
    )

    new DataWritersStatsEngine(dataWriterInitMessage, dataWriters, system, clock)
  }
}

class DataWritersStatsEngine(dataWriterInitMessage: Init, dataWriters: Seq[ActorRef], system: ActorSystem, clock: Clock) extends StatsEngine {

  private val active = new AtomicBoolean(true)

  override def start(): Unit = {

    implicit val dataWriterTimeOut: Timeout = Timeout(5 seconds)
    implicit val dispatcher: ExecutionContext = system.dispatcher

    val dataWriterInitResponses = dataWriters.map(_ ? dataWriterInitMessage)

    val statsEngineFuture: Future[Unit] = Future
      .sequence(dataWriterInitResponses)
      .flatMap { responses =>
        if (responses.forall(_ == true)) {
          Future.unit
        } else {
          Future.failed(new Exception("DataWriters didn't initialize properly"))
        }

      }

    Await.ready(statsEngineFuture, dataWriterTimeOut.duration)
  }

  override def stop(replyTo: ActorRef, exception: Option[Exception]): Unit =
    if (active.getAndSet(false)) {
      implicit val dispatcher: ExecutionContext = system.dispatcher
      implicit val dataWriterTimeOut: Timeout = Timeout(5 seconds)
      val responses = dataWriters.map(_ ? Stop)
      Future.sequence(responses).onComplete(_ => replyTo ! ControllerCommand.StatsEngineStopped)
    }

  private def dispatch(message: DataWriterMessage): Unit = if (active.get) dataWriters.foreach(_ ! message)

  override def logUserStart(session: Session): Unit = dispatch(UserStartMessage(session))

  override def logUserEnd(userMessage: UserEndMessage): Unit = dispatch(userMessage)

  // [fl]
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  //
  // [fl]

  override def logResponse(
      session: Session,
      requestName: String,
      startTimestamp: Long,
      endTimestamp: Long,
      status: Status,
      responseCode: Option[String],
      message: Option[String]
  ): Unit =
    if (endTimestamp >= 0) {
      dispatch(
        ResponseMessage(
          session.scenario,
          session.userId,
          session.groupHierarchy,
          requestName,
          startTimestamp,
          endTimestamp,
          status,
          responseCode,
          message
        )
      )
    }

  override def logGroupEnd(
      session: Session,
      group: GroupBlock,
      exitTimestamp: Long
  ): Unit =
    dispatch(
      GroupMessage(
        session.scenario,
        session.userId,
        group.hierarchy,
        group.startTimestamp,
        exitTimestamp,
        group.cumulatedResponseTime,
        group.status
      )
    )

  override def logCrash(session: Session, requestName: String, error: String): Unit =
    dispatch(ErrorMessage(s"$requestName: $error ", clock.nowMillis))
}
