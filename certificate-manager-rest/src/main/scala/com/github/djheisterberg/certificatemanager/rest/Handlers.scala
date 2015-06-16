import java.util.Date

import scala.concurrent.ExecutionContext
import scala.concurrent.Future

import org.vertx.scala.core.MultiMap
import org.vertx.scala.core.buffer.Buffer
import org.vertx.scala.core.http.HttpServerRequest
import org.vertx.scala.core.json.Json
import org.vertx.scala.core.json.JsonArray
import org.vertx.scala.core.json.JsonElement
import org.vertx.scala.core.json.JsonObject

package com.github.djheisterberg.certificatemanager {

  import service._

  package rest {

    class Handlers(private val certMgrSvc: CertificateManagerService, implicit private val executionContext: ExecutionContext) {

      def rootInfo(request: HttpServerRequest) {
        val jsonCertificateInfos = certMgrSvc.getRootInfo() map seqToJSON(certificateInfoToJSON)
        writeJSON(request, jsonCertificateInfos)
      }

      def issuedInfo(request: HttpServerRequest) {

        val issuerAlias = singletonParameter(request.params())("issuerAlias")

        val jsonCertificateInfos = certMgrSvc.getIssuedInfo(issuerAlias) map seqToJSON(certificateInfoToJSON)
        writeJSON(request, jsonCertificateInfos)
      }

      def root(request: HttpServerRequest) {
        val params = request.params()
        val paramOption = singletonParameterOption(params) _
        val param = singletonParameter(paramOption) _

        val alias = param("alias")
        val password = param("password").toCharArray
        val subject = param("subject")
        val alternativeName = paramOption("alternativeName")
        val keyAlgorithm = param("keyAlgorithm")
        val keyParam: certMgrSvc.KeyParam = {
          val keyParam = param("keyParam")
          try {
            Left(keyParam.toInt)
          } catch {
            case nfe: NumberFormatException => Right(keyParam)
          }
        }
        val sigAlgorithm = param("sigAlgorithm")
        val notBefore = new Date(param("notBefore").toLong)
        val notAfter = new Date(param("notAfter").toLong)

        certMgrSvc.createRootCertificate(alias, password, subject, alternativeName,
          keyAlgorithm, keyParam, sigAlgorithm, notBefore, notAfter)
      }

      private def singletonParameterOption(params: MultiMap)(key: String) = (params get key) map (_.head)

      private def singletonParameter(op: (String) => Option[String])(key: String) = op(key) match {
        case Some(value) => value
        case None => throw new RequestErrorException(s"Missing $key parameter")
      }

      private def singletonParameter(params: MultiMap)(key: String): String = singletonParameter(singletonParameterOption(params) _)(key)

      private def writeJSON(request: HttpServerRequest, jsonF: Future[JsonElement]) {
        val response = request.response()
        jsonF map { json =>
          val buffer = Buffer(json.toString.getBytes("UTF-8"))
          response.putHeader("Content-Type", "application/json; charset=UTF-8")
          response.putHeader("Content-Length", buffer.length.toString)
          response.write(buffer)
          response.end
        }
      }

      private def certificateInfoToJSON(certInfo: CertificateInfo) =
        Json.obj("alias" -> certInfo.alias, "issuerAlias" -> certInfo.issuerAlias, "subject" -> certInfo.subject, "notBefore" -> certInfo.notBefore.getTime, "notAfter" -> certInfo.notAfter.getTime)

      private def appendToJSON[A](toJSON: A => JsonObject)(ja: JsonArray, a: A) = ja.addObject(toJSON(a))

      private def seqToJSON[A](toJSON: A => JsonObject)(seq: A*) = (Json.emptyArr() /: seq)(appendToJSON(toJSON))
    }
  }
}
