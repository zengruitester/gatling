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

package io.gatling.core.structure

import java.util.UUID

import scala.concurrent.duration.Duration

import io.gatling.commons.util.Clock
import io.gatling.core.action.builder._
import io.gatling.core.session._

import com.eatthepath.uuid.FastUUID

private[structure] trait Loops[B] extends Execs[B] {

  @SuppressWarnings(Array("org.wartremover.warts.DefaultArguments"))
  // binary compat
  def repeat(times: Expression[Int], counterName: String = FastUUID.toString(UUID.randomUUID))(chain: ChainBuilder): B = {

    val continueCondition = (session: Session) => times(session).map(session.loopCounterValue(counterName) < _)

    loop(continueCondition, chain, counterName, exitASAP = false, RepeatLoopType)
  }

  @SuppressWarnings(Array("org.wartremover.warts.DefaultArguments"))
  // binary compat
  def foreach(seq: Expression[Seq[Any]], attributeName: String, counterName: String = FastUUID.toString(UUID.randomUUID))(chain: ChainBuilder): B = {

    val exposeCurrentValue = (session: Session) => seq(session).map(seq => session.set(attributeName, seq(session.loopCounterValue(counterName))))
    val continueCondition = (session: Session) => seq(session).map(_.size > session.loopCounterValue(counterName))

    loop(
      continueCondition,
      ChainBuilder(List(new SessionHookBuilder(exposeCurrentValue, exitable = false))).exec(chain),
      counterName,
      exitASAP = false,
      ForeachLoopType
    )
  }

  @SuppressWarnings(Array("org.wartremover.warts.DefaultArguments"))
  // binary compat
  def during(duration: Duration, counterName: String = FastUUID.toString(UUID.randomUUID), exitASAP: Boolean = true)(
      chain: ChainBuilder
  )(implicit clock: Clock): B =
    during(duration.expressionSuccess, counterName, exitASAP)(chain)

  def during(duration: Expression[Duration], counterName: String, exitASAP: Boolean)(chain: ChainBuilder)(implicit clock: Clock): B = {

    val continueCondition = (session: Session) => duration(session).map(d => clock.nowMillis - session.loopTimestampValue(counterName) <= d.toMillis)

    loop(continueCondition, chain, counterName, exitASAP, DuringLoopType)
  }

  def forever(chain: ChainBuilder): B = forever(FastUUID.toString(UUID.randomUUID))(chain)

  @SuppressWarnings(Array("org.wartremover.warts.DefaultArguments"))
  // binary compat
  def forever(counterName: String = FastUUID.toString(UUID.randomUUID), exitASAP: Boolean = false)(chain: ChainBuilder): B =
    loop(TrueExpressionSuccess, chain, counterName, exitASAP, ForeachLoopType)

  @SuppressWarnings(Array("org.wartremover.warts.DefaultArguments"))
  // binary compat
  def asLongAs(condition: Expression[Boolean], counterName: String = FastUUID.toString(UUID.randomUUID), exitASAP: Boolean = false)(chain: ChainBuilder): B =
    loop(condition, chain, counterName, exitASAP, AsLongAsLoopType)

  @SuppressWarnings(Array("org.wartremover.warts.DefaultArguments"))
  // binary compat
  def doWhile(condition: Expression[Boolean], counterName: String = FastUUID.toString(UUID.randomUUID))(chain: ChainBuilder): B =
    loop(condition, chain, counterName, exitASAP = false, DoWhileType)

  private def loop(
      condition: Expression[Boolean],
      chain: ChainBuilder,
      counterName: String,
      exitASAP: Boolean,
      loopType: LoopType
  ): B =
    exec(new LoopBuilder(condition, chain, counterName, exitASAP, loopType))

  private def continueCondition(condition: Expression[Boolean], duration: Expression[Duration], counterName: String, clock: Clock) =
    (session: Session) =>
      for {
        durationValue <- duration(session)
        conditionValue <- condition(session)
      } yield clock.nowMillis - session.loopTimestampValue(counterName) <= durationValue.toMillis && conditionValue

  @SuppressWarnings(Array("org.wartremover.warts.DefaultArguments"))
  // binary compat
  def asLongAsDuring(
      condition: Expression[Boolean],
      duration: Expression[Duration],
      counterName: String = FastUUID.toString(UUID.randomUUID),
      exitASAP: Boolean = true
  )(chain: ChainBuilder)(implicit clock: Clock): B =
    loop(continueCondition(condition, duration, counterName, clock), chain, counterName, exitASAP, AsLongAsDuringLoopType)

  @SuppressWarnings(Array("org.wartremover.warts.DefaultArguments"))
  // binary compat
  def doWhileDuring(
      condition: Expression[Boolean],
      duration: Expression[Duration],
      counterName: String = FastUUID.toString(UUID.randomUUID),
      exitASAP: Boolean = true
  )(chain: ChainBuilder)(implicit clock: Clock): B =
    loop(continueCondition(condition, duration, counterName, clock), chain, counterName, exitASAP, DoWhileDuringType)
}
