import akka.actor.Actor
import akka.actor.ActorLogging
import akka.actor.ActorRef
import akka.actor.ActorSystem
import akka.actor.Props
import akka.actor.Terminated

package com.github.djheisterberg.certificatemanager.rest {

  object ARun {

    def main(args: Array[String]) {
      val system = ActorSystem("Echo")
      val echo = system.actorOf(Props[EchoActor], "echo")
      system.actorOf(Props(classOf[Terminator], echo), "terminator")

      echo ! this
      echo ! "a string"
      echo ! EchoActor.Shutdown
    }

    class Terminator(ref: ActorRef) extends Actor with ActorLogging {
      context watch ref

      def receive = {
        case Terminated(_) =>
          log.info("{} has terminated, shutting down system", ref.path)
          context.system.shutdown()
      }
    }
  }
}