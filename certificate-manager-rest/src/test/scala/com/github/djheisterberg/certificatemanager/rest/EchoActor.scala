import akka.actor.Actor

package com.github.djheisterberg.certificatemanager.rest {

  object EchoActor {
    object Shutdown
  }

  class EchoActor extends Actor {

    override def receive = {
      case EchoActor.Shutdown => context stop self
      case msg: Any => println("Received " + msg + " (" + msg.getClass.getName + ")")
    }
  }
}