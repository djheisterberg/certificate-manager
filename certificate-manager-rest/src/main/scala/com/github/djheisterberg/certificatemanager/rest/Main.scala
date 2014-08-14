import org.vertx.scala.core.`package`.newVertx
import org.vertx.scala.core.http.HttpServerRequest

package com.github.djheisterberg.certificatemanager {
  package rest {

    object Main {
      def main(args: Array[String]) {
        val vertx = newVertx()

        val httpServer = vertx.createHttpServer()
      }
    }
  }
}
