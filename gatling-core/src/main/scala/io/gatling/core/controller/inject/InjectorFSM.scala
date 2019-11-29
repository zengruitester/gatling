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

package io.gatling.core.controller.inject

import io.gatling.core.akka.BaseActor
import io.gatling.core.scenario.Scenario

import akka.actor.{ ActorRef, Cancellable, FSM }

private[inject] trait InjectorState
private[inject] object InjectorState {
  case object WaitingToStart extends InjectorState
  case object Started extends InjectorState
}

private[inject] trait InjectorData
private[inject] object InjectorData {
  case object NoData extends InjectorData
  final case class StartedData(
      controller: ActorRef,
      inProgressWorkloads: Map[String, Workload],
      todoScenarios: List[Scenario],
      pendingChildrenScenarios: Map[String, List[Scenario]],
      timer: Cancellable
  ) extends InjectorData
}

private[inject] class InjectorFSM extends BaseActor with FSM[InjectorState, InjectorData]

private[inject] class UserCounts {

  private[this] var _started: Long = 0
  private[this] var _stopped: Long = 0

  def started: Long = _started

  def incrementStarted(more: Long): Unit = _started += more
  def incrementStopped(): Unit = _stopped += 1

  def allStopped: Boolean = started == _stopped
}
