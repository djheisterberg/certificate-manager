import scala.concurrent.ExecutionContext
import scala.concurrent.Future

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

        val issuerAlias = request.params().get("issuerAlias") match {
          case Some(issuerAliasSet) => {
            if (issuerAliasSet.size == 1) issuerAliasSet.head
            else throw new RequestErrorException("Multiple issuerAlias parameters not supported")
          }
          case None => throw new RequestErrorException("Missing issuerAlias parameter")
        }

        val jsonCertificateInfos = certMgrSvc.getIssuedInfo(issuerAlias) map seqToJSON(certificateInfoToJSON)
        writeJSON(request, jsonCertificateInfos)
      }

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
