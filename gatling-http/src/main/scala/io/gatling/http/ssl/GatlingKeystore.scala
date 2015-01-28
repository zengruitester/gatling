package io.gatling.http.ssl

import java.io.{ IOException, InputStream }
import java.security.cert.X509Certificate
import java.security.{ KeyStore, PrivateKey }

import io.gatling.core.util.RoundRobin
import io.gatling.http.ssl.GatlingKeystore.{ CertsMap, PrivateKeysMap }

import scala.collection.JavaConversions._

class GatlingKeystore(keystore: KeyStore,
                      val allAliases: Vector[String],
                      privateKeyByAlias: PrivateKeysMap,
                      certsByAlias: CertsMap) {

  //Using a RR avoids synchronized block
  val rrAliases: Iterator[String] = {
    if (allAliases.nonEmpty)
      RoundRobin(allAliases)
    else
      throw new IOException("Cannot create round robin aliases from no aliases")
  }

  def getCertificateChain(alias: String): Array[X509Certificate] = {
    certsByAlias.getOrElse(alias, throw new IllegalArgumentException(s"No certificate found for alias: $alias"))
  }

  def getPrivateKey(alias: String): PrivateKey = {
    privateKeyByAlias.getOrElse(alias, throw new IllegalArgumentException(s"No private key found for alias: $alias"))
  }

  def getAlias = rrAliases.next()

  def getAlias(index: Int) = allAliases(index)

}

object GatlingKeystore {

  //Type aliases for immutable maps
  type PrivateKeysMap = Map[String, PrivateKey]
  type CertsMap = Map[String, Array[X509Certificate]]
  def PrivateKeysMap = Map[String, PrivateKey]()
  def CertsMap = Map[String, Array[X509Certificate]]()

  def getLoadedInstance(is: InputStream, pass: Array[Char], storeType: String): GatlingKeystore = {
    val keystore = KeyStore.getInstance(storeType)
    val storePass = Option(pass).orNull
    keystore.load(is, storePass)

    Option(is).map { stream =>
      val aliases = keystore.aliases.toList
      val filteredAliases = aliases.filter(keystore.isKeyEntry).toVector
      val (privateKeyByAlias, certsByAlias) = filteredAliases.foldLeft(PrivateKeysMap, CertsMap) {
        case ((pKeysByAlias, crtsByAlias), alias) =>
          val privateKey = Option(keystore.getKey(alias, storePass).asInstanceOf[PrivateKey]).getOrElse(throw new IOException(s"No key found for alias: $alias"))
          val certs: Array[X509Certificate] = Option(keystore.getCertificateChain(alias))
            .getOrElse(throw new IOException(s"No certificate chain found for alias: $alias"))
            .map(_.asInstanceOf[X509Certificate])
          (pKeysByAlias + (alias -> privateKey), crtsByAlias + (alias -> certs))
      }
      new GatlingKeystore(keystore, filteredAliases, privateKeyByAlias, certsByAlias)
    }.get
  }

}
