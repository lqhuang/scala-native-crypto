package com.github.lolgab.scalanativecrypto

import java.com.github.lolgab.scalanativecrypto.internal.CtxFinalizer

import scala.scalanative.meta.LinktimeInfo
import scala.scalanative.unsafe.CQuote

import internal.crypto.OSSL_LIB_CTX_*
import internal.crypto.{
  OSSL_LIB_CTX_new,
  OSSL_PROVIDER_available,
  OSSL_PROVIDER_load
}

private[scalanativecrypto] object AppLibCtx {

  final val osslLibCtx: OSSL_LIB_CTX_* = OSSL_LIB_CTX_new()

  if (LinktimeInfo.isWeakReferenceSupported) {
    CtxFinalizer.register_OSSL_LIB_CTX(this, osslLibCtx)
  } else {
    System.err.println(
      "[java.security.Provider] OpenSSL context finalization is not supported. Consider using immix or commix GC, otherwise this will leak memory."
    )
  }

  def loadLegacyProvider(): Unit = {
    if (OSSL_PROVIDER_available(osslLibCtx, c"legacy") == 1)
      OSSL_PROVIDER_load(osslLibCtx, c"legacy")
    else
      System.err.println(
        "[java.security.Provider] OpenSSL legacy provider is not available, Some algorithms may not work"
      )
  }

  def loadDefaultProvider(): Unit =
    OSSL_PROVIDER_load(osslLibCtx, c"default")

}
