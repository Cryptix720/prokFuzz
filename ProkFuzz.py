#!/usr/bin/python
from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator

from java.util import List, ArrayList

import random

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):
  def registerExtenderCallbacks(self, callbacks):
    self._callbacks = callbacks
    self._helpers = callbacks.getHelpers()
    callbacks.registerIntruderPayloadGeneratorFactory(self)
    return

def generatorName(name):
  return "Payload generator"

def reuseNewInstance(self, action):
  return ProkFuzz(self, action)

class ProKFuzz(IIntruderPayloadGenerator):
  def __init__(self, extender, action):
    self._extender = extender
    self._helpers = extender._helpers
    self._action = action
    self.min_payloads = 1
    self.max_payloads = 10
    self.num_iterators = 0

    return


  def morePayloads(self):
    if self.num_iterators == self.max_payloads:
      return false
    else:
      return true

    def nextPayload(self, current_payload):
      payload ="".join(chr(x) for x in current_payload)
      payload = self.mutate_payload(payload)
      self.sum_iterations += 1
      return payload


    def reset(self):
      self.num_iterators =0
      return

    def mutate_payload(self, original_payload):
      picker = random.randint(1,5)
      offset = random.randint(0,len(original_payload)-1)
      payload =  original_payload[:offset]
      if picker == 1:
        payload += "'"
        if picker ==2:
          payload += "<script>alert('Jamming. %s');</script>"
          if picker == 3:
            chunk_length = random.randint(len(payload[offset:]),len(payload)-1)
            repeater = random.randint(1,22)

            for i in range(repeater):
              payload += original_payload[offset:offset+chunk_length]
              payload += original_payload[offset:]
              return payload
	
	
