package io.gatling.http.ssl

import java.net.Socket
import java.security.{ PrivateKey, Principal }
import java.security.cert.X509Certificate
import javax.net.ssl.{ X509ExtendedKeyManager, X509KeyManager }

/**
 * Created by excilys on 26/01/15.
 */
class GatlingKeyManager(manager: X509KeyManager, store: GatlingKeystore) extends X509ExtendedKeyManager {

  val aliasesAsArray = store.allAliases.toArray

  override def getClientAliases(keyType: String, principals: Array[Principal]): Array[String] = aliasesAsArray

  override def getPrivateKey(alias: String): PrivateKey = store.getPrivateKey(alias)

  override def getCertificateChain(alias: String): Array[X509Certificate] = store.getCertificateChain(alias)

  override def getServerAliases(keyType: String, principals: Array[Principal]): Array[String] = manager.getServerAliases(keyType, principals)

  override def chooseClientAlias(strings: Array[String], principals: Array[Principal], socket: Socket): String = store.getAlias

  override def chooseServerAlias(keyType: String, principals: Array[Principal], socket: Socket): String = manager.chooseServerAlias(keyType, principals, socket)
}
