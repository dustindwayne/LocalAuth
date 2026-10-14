package com.localauth

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo

class HomeDiscovery(context:Context,private val found:()->Unit) {
 private val manager=context.getSystemService(NsdManager::class.java)
 private var listener:NsdManager.DiscoveryListener?=null
 fun start() {
  if(listener!=null)return
  val l=object:NsdManager.DiscoveryListener {
   override fun onDiscoveryStarted(type:String) {}
   override fun onServiceFound(info:NsdServiceInfo) {if(info.serviceType.trimEnd('.')=="_localauth._tcp")found()}
   override fun onServiceLost(info:NsdServiceInfo) {}
   override fun onDiscoveryStopped(type:String) {}
   override fun onStartDiscoveryFailed(type:String,error:Int) {stop()}
   override fun onStopDiscoveryFailed(type:String,error:Int) {listener=null}
  }
  listener=l
  try{manager.discoverServices("_localauth._tcp.",NsdManager.PROTOCOL_DNS_SD,l)}catch(_:Exception){listener=null}
 }
 fun stop(){val l=listener?:return;listener=null;try{manager.stopServiceDiscovery(l)}catch(_:Exception){}}
}
