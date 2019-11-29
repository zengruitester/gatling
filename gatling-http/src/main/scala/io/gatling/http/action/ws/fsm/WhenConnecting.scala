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

package io.gatling.http.action.ws.fsm

import io.gatling.commons.stats.{ KO, OK }
import io.gatling.commons.util.Throwables._
import io.gatling.core.action.Action
import io.gatling.core.session.Session
import io.gatling.http.action.ws.{ OnConnectedChainEndAction, WsListener }
import io.gatling.http.cache.SslContextSupport
import io.gatling.http.check.ws.WsFrameCheckSequence
import io.gatling.http.cookie.CookieSupport

import io.netty.handler.codec.http.HttpResponseStatus.SWITCHING_PROTOCOLS

object WhenConnecting {

  private val WsConnectSuccessStatusCode = Some(Integer.toString(SWITCHING_PROTOCOLS.code))
}

trait WhenConnecting extends SslContextSupport { this: WsActor =>

  def gotoConnecting(session: Session, next: Either[Action, SendFrame]): State =
    gotoConnecting(session, next, httpProtocol.wsPart.maxReconnects.getOrElse(0))

  def gotoConnecting(session: Session, next: Either[Action, SendFrame], remainingTries: Int): State = {

    val listener = new WsListener(self, statsEngine, clock)

    // [fl]
    //
    // [fl]
    val userSslContexts = sslContexts(session)
    httpEngine.executeRequest(
      connectRequest,
      session.userId,
      httpProtocol.enginePart.shareConnections,
      listener,
      userSslContexts.map(_.sslContext).orNull,
      userSslContexts.flatMap(_.alpnSslContext).orNull
    )

    goto(Connecting) using ConnectingData(session, next, clock.nowMillis, remainingTries)
  }

  private def handleConnectFailure(
      session: Session,
      next: Either[Action, SendFrame],
      connectStart: Long,
      connectEnd: Long,
      code: Option[String],
      reason: String,
      remainingTries: Int
  ): State = {
    // log connect failure
    val newSession = logResponse(session, connectActionName, connectStart, connectEnd, KO, code, Some(reason))
    val newRemainingTries = remainingTries - 1
    if (newRemainingTries > 0) {
      // try again
      logger.debug(s"Connect failed: $code:$reason, retrying ($newRemainingTries remaining tries)")
      gotoConnecting(newSession, next, newRemainingTries)

    } else {
      val nextAction = next match {
        case Left(n) =>
          // failed to connect
          logger.debug(s"Connect failed: $code:$reason, no remaining tries, going to Crashed state and performing next action")
          n
        case Right(sendFrame) =>
          // failed to reconnect, logging failure to send message
          logger.debug(s"Connect failed: $code:$reason, no remaining tries, going to Crashed state, failing pending Send and performing next action")
          statsEngine.logCrash(newSession, sendFrame.actionName, "Failed to reconnect")
          sendFrame.next
      }
      nextAction ! newSession.markAsFailed
      goto(Crashed) using CrashedData(Some(reason))
    }
  }

  when(Connecting) {
    case Event(WebSocketConnected(webSocket, cookies, connectEnd), ConnectingData(session, next, connectStart, _)) =>
      val sessionWithCookies = CookieSupport.storeCookies(session, connectRequest.getUri, cookies, connectEnd)
      val sessionWithGroupTimings =
        logResponse(sessionWithCookies, connectActionName, connectStart, connectEnd, OK, WhenConnecting.WsConnectSuccessStatusCode, None)

      connectCheckSequence match {
        case WsFrameCheckSequence(timeout, currentCheck :: remainingChecks) :: remainingCheckSequences =>
          // wait for some checks before proceeding

          // select nextAction
          val (newSession, newNext) =
            onConnected match {
              case Some(onConnectedAction) =>
                // once check complete, perform connect sequence
                // we store the after next action in the session
                // other solution would be to store in FSM state but we'd need one more message passing to contact the actor from ConnectSequenceEndAction

                val onConnectedChainEndCallback: Session => Unit = next match {
                  case Left(nextAction) =>
                    logger.debug("Connected, performing checks, setting callback to perform next action after performing onConnected action")
                    nextAction ! _

                  case Right(sendTextMessage) =>
                    logger.debug("Connected, performing checks, setting callback to send pending message after performing onConnected action")
                    s => self ! sendTextMessage.copyWithSession(s)
                }

                (OnConnectedChainEndAction.setOnConnectedChainEndCallback(sessionWithGroupTimings, onConnectedChainEndCallback), Left(onConnectedAction))

              case _ =>
                // once check complete -> send next
                logger.debug("Connected, performing checks before proceeding (no onConnected action)")
                (sessionWithGroupTimings, next)
            }

          val timeoutId = scheduleTimeout(timeout)
          //[fl]
          //
          //[fl]
          goto(PerformingCheck) using PerformingCheckData(
            webSocket = webSocket,
            currentCheck = currentCheck,
            remainingChecks = remainingChecks,
            checkSequenceStart = connectEnd,
            checkSequenceTimeoutId = timeoutId,
            remainingCheckSequences = remainingCheckSequences,
            session = newSession,
            next = newNext
          )

        case _ => // same as Nil as WsFrameCheckSequence#checks can't be Nil, but compiler complains that match may not be exhaustive
          onConnected match {
            case Some(onConnectedAction) =>
              // connect sequence -> store actual next
              val onConnectedChainEndCallback: Session => Unit = next match {
                case Left(nextAction) =>
                  logger.debug("Connected, no checks, performing onConnected action before performing next action")
                  nextAction ! _

                case Right(sendFrame) =>
                  logger.debug("Reconnected, no checks, performing onConnected action before sending pending message")
                  s => self ! sendFrame.copyWithSession(s)
              }
              val newSession = OnConnectedChainEndAction.setOnConnectedChainEndCallback(sessionWithGroupTimings, onConnectedChainEndCallback)
              onConnectedAction ! newSession
              goto(Idle) using IdleData(newSession, webSocket)

            case _ =>
              // send next
              next match {
                case Left(nextAction) =>
                  logger.debug("Connected, no checks, performing next action")
                  nextAction ! sessionWithGroupTimings

                case Right(sendFrame) =>
                  logger.debug("Reconnected, no checks, sending pending message")
                  self ! sendFrame.copyWithSession(sessionWithGroupTimings)
              }
              goto(Idle) using IdleData(sessionWithGroupTimings, webSocket)
          }
      }

    case Event(WebSocketClosed(code, reason, timestamp), ConnectingData(session, next, connectStart, remainingTries)) =>
      // unexpected close
      handleConnectFailure(session, next, connectStart, timestamp, Some(String.valueOf(code)), reason, remainingTries)

    case Event(WebSocketCrashed(t, timestamp), ConnectingData(session, next, connectStart, remainingTries)) =>
      // crash
      logger.debug("WebSocket crashed", t)
      handleConnectFailure(session, next, connectStart, timestamp, None, t.rootMessage, remainingTries)
  }
}
