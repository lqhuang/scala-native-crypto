package com.github.lolgab.scalanativecrypto.crypto

import java.io.{InputStream, OutputStream}
import java.io.IOException
import java.nio.charset.StandardCharsets.UTF_8
import java.security.{Key, Provider, KeyStore, KeyStoreSpi}
import java.security.{UnrecoverableKeyException, KeyStoreException}
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.util.{Date, Enumeration, Collections}
import java.util.{Set => JSet}
import java.util.Objects.requireNonNull
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock
import java.com.github.lolgab.scalanativecrypto.internal.CtxFinalizer

import scala.scalanative.unsafe.{
  Ptr,
  Zone,
  toCString,
  fromCStringSlice,
  alloc,
  stackalloc
}
import scala.scalanative.unsigned.UnsignedRichInt
import scala.scalanative.meta.LinktimeInfo
import scala.scalanative.annotation.alwaysinline

import com.github.lolgab.scalanativecrypto.internal.crypto
import com.github.lolgab.scalanativecrypto.internal.crypto.{
  PKCS12_*,
  X509_*,
  EVP_PKEY_*,
  stack_st_X509
}
import com.github.lolgab.scalanativecrypto.crypto.cert.OpenSSLX509Certificate

final class OpenSSLKeyStore(provider: Provider, ksType: String)
    extends KeyStore(new OpenSSLKeyStoreSpi(), provider, ksType)

final class OpenSSLKeyStoreSpi protected[scalanativecrypto]
    extends KeyStoreSpi {

  @volatile
  private var pkey: EVP_PKEY_* = null
  @volatile
  private var pkcs: PKCS12_* = null
  @volatile
  private var cert: X509_* = null
  @volatile
  private var stackOfCA: Ptr[stack_st_X509] = null

  private val isLoaded = new AtomicBoolean(false)
  private val ptrLock = new ReentrantLock()

  if (LinktimeInfo.isWeakReferenceSupported) {
    CtxFinalizer.register_EVP_PKEY(this, pkey)
    CtxFinalizer.register_PKCS12(this, pkcs)
    CtxFinalizer.register_X509(this, cert)
    CtxFinalizer.register_StackOfX509(this, stackOfCA)
  } else {
    System.err.println(
      "[java.security.KeyStore] OpenSSL context finalization is not supported. Consider using immix or commix GC, otherwise this will leak memory."
    )
  }

  override def engineGetKey(alias: String, password: Array[Char]): Key = {
    throwIfNotLoaded()
    ???
  }

  // Implement details: Always returns a copy of the certificate chain
  override def engineGetCertificateChain(alias: String): Array[Certificate] = {
    throwIfNotLoaded()
    buildX509Chain(cert, stackOfCA).asInstanceOf[Array[Certificate]]
  }

  // Implement details: Always returns a copy of the certificate
  override def engineGetCertificate(alias: String): Certificate = {
    throwIfNotLoaded()

    if (alias == "1") {
      val chain = engineGetCertificateChain(alias)
      if (chain != null && !chain.isEmpty) chain(0) else null
    } else {
      // TODO: not implemented yet
      null
    }
  }

  override def engineGetCreationDate(alias: String): Date = {
    throwIfNotLoaded()

    if (alias == "1") {
      ???
    } else {
      // TODO: not implemented yet
      null
    }
  }

  override def engineSetKeyEntry(
      alias: String,
      key: Key,
      password: Array[Char],
      chain: Array[Certificate]
  ): Unit = {
    throwIfNotLoaded()
    ???
  }

  override def engineSetKeyEntry(
      alias: String,
      key: Array[Byte],
      chain: Array[Certificate]
  ): Unit = {
    throwIfNotLoaded()
    ???
  }

  override def engineSetCertificateEntry(
      alias: String,
      cert: Certificate
  ): Unit = {
    throwIfNotLoaded()
    ???
  }

  override def engineDeleteEntry(alias: String): Unit = {
    throwIfNotLoaded()
    ???
  }

  // TODO:
  //
  // This will copy the alias string every time when invoked.
  // We can optimize this by caching the alias in a field when loading the KeyStore.
  // But don't forget that KeyStore can be reloaded when refactoring the code in the future.
  override def engineAliases(): Enumeration[String] = {
    throwIfNotLoaded()

    if (cert == null)
      Collections.emptyEnumeration()
    else {
      val alias = getX509Alias(cert)
      if (alias.isEmpty())
        Collections.emptyEnumeration()
      else
        Collections.enumeration(Collections.singletonList(alias))
    }
  }

  override def engineContainsAlias(alias: String): Boolean = {
    throwIfNotLoaded()
    Collections.list(engineAliases()).contains(alias)
  }

  override def engineSize(): Int = {
    throwIfNotLoaded()
    if (cert != null) 1 else 0
  }

  override def engineIsKeyEntry(alias: String): Boolean = {
    throwIfNotLoaded()
    ???
  }

  override def engineIsCertificateEntry(alias: String): Boolean = {
    throwIfNotLoaded()
    ???
  }

  override def engineGetCertificateAlias(cert: Certificate): String = {
    throwIfNotLoaded()
    ???
  }

  override def engineStore(
      stream: OutputStream,
      password: Array[Char]
  ): Unit = {
    throwIfNotLoaded()
    ???
  }

  override def engineStore(param: KeyStore.LoadStoreParameter): Unit = {
    throwIfNotLoaded()
    ???
  }

  override def engineLoad(stream: InputStream, password: Array[Char]): Unit = {
    if (stream == null)
      throw new NotImplementedError(
        "Creating an empty KeyStore or loading from null InputStream is not supported yet"
      )

    isLoaded.compareAndExchange(false, true)
    loadFromStream(
      stream,
      if (password == null) Array.emptyCharArray else password
    )
  }

  override def engineLoad(param: KeyStore.LoadStoreParameter): Unit = {
    requireNonNull(
      param,
      "the param (KeyStore.LoadStoreParameter) must be non-null"
    )

    if (!isLoaded.compareAndExchange(false, true))
      throw new IOException("the KeyStore has already been loaded")
    else {
      ???
    }
  }

  // @since JDK 18
  override def engineGetAttributes(
      alias: String
  ): JSet[KeyStore.Entry.Attribute] = {
    requireNonNull(alias, "the alias must be non-null")
    throwIfNotLoaded()
    ???
  }

  override def engineGetEntry(
      alias: String,
      protectionParam: KeyStore.ProtectionParameter
  ): KeyStore.Entry = {
    requireNonNull(alias, "the alias must be non-null")
    throwIfNotLoaded()

    if (!engineContainsAlias(alias)) {
      null
    } else {
      ???
    }
  }

  override def engineSetEntry(
      alias: String,
      entry: KeyStore.Entry,
      protParam: KeyStore.ProtectionParameter
  ): Unit = {
    requireNonNull(alias, "the alias must be non-null")
    throwIfNotLoaded()
    ???
  }

  override def engineEntryInstanceOf(
      alias: String,
      entryClass: Class[_ <: KeyStore.Entry]
  ): Boolean = {
    requireNonNull(alias, "the alias must be non-null")
    throwIfNotLoaded()
    ???
  }

  // @since JDK 9
  override def engineProbe(stream: InputStream): Boolean =
    ???

  /*
   * Private helper methods
   */

  @alwaysinline
  private def throwIfNotLoaded(): Unit =
    if (!isLoaded.get())
      throw new KeyStoreException(
        "the keystore has not been initialized (loaded)."
      )

  /**
   * @param stream
   *   Cannot be null.
   * @param password
   *   Cannot be null, but can be empty.
   */
  @alwaysinline
  private def loadFromStream(
      stream: InputStream,
      password: Array[Char]
  ): Unit = {
    requireNonNull(stream, "the input stream must be non-null.")

    if (stream.markSupported()) stream.mark(stream.available() + 1)
    val bytes = stream.readAllBytes()
    if (bytes.isEmpty)
      throw new IOException("the InputStream is empty")

    Zone.acquire { implicit zone =>
      val memBuf = alloc[Byte](bytes.length)
      for (i <- bytes.indices) memBuf(i) = bytes(i)

      // As OpenSSL Docs:
      // > The parameter pass is interpreted as a string in the UTF-8 encoding.
      // > If it is not valid UTF-8, then it is assumed to be ISO8859-1 instead.
      val passwdBuf =
        toCString(new String(password.mkString.getBytes(), UTF_8))

      val bio = crypto.BIO_new_mem_buf(memBuf, bytes.length)
      try {
        val p12Handle = crypto.d2i_PKCS12_bio(bio, null)
        if (p12Handle == null)
          throw new IOException("failed to parse the PKCS#12 data")

        val _pkey = stackalloc[EVP_PKEY_*]()
        val _x509 = stackalloc[X509_*]()
        val _stackOfX509 =
          stackalloc[Ptr[stack_st_X509]]() // Improvable: should be init as NULL

        val verified =
          crypto.PKCS12_verify_mac(p12Handle, passwdBuf, password.length)
        if (verified == 0)
          throw new IOException(
            "failed to verify the PKCS#12 data",
            new UnrecoverableKeyException(
              "the provided password is incorrect"
            )
          )

        val ret = crypto.PKCS12_parse(
          p12Handle,
          passwdBuf,
          _pkey,
          _x509,
          _stackOfX509
        )
        if (ret == 0) {
          // fetch error via ERR_get_error
          // println(s"OpenSSL error code: ${ret}")
          throw new CertificateException("failed to parse the PKCS#12 data")
        }

        ptrLock.lock()
        try {
          pkcs = p12Handle
          pkey = !_pkey
          cert = !_x509
          stackOfCA = !_stackOfX509
        } // force new line
        finally ptrLock.unlock()
      } // force new line
      finally {
        crypto.BIO_free(bio)
      }
    }
  }

  private def buildX509Chain(
      cert: X509_*,
      skCA: Ptr[stack_st_X509]
  ): Array[OpenSSLX509Certificate] = {
    val numCA = {
      val n = crypto.sncrypto_ossl_sk_X509_num(skCA)
      if (n < 0) 0 else n
    }
    val numCert = if (cert != null) 1 else 0
    val total = numCert + numCA
    val chain = new Array[OpenSSLX509Certificate](total)

    if (cert != null) {
      chain(0) = new OpenSSLX509Certificate(x509DupOrUpRefByCheckPurpose(cert))
    }

    for (i <- 0 until numCA) {
      val each = crypto.sncrypto_ossl_sk_X509_value(skCA, i)
      chain(i + numCert) = new OpenSSLX509Certificate(
        x509DupOrUpRefByCheckPurpose(each)
      )
    }

    chain
  }

  @alwaysinline
  private def x509DupOrUpRefByCheckPurpose(cert: X509_*): X509_* = {
    val dup = crypto.X509_dup(cert)
    if (dup == null)
      throw new RuntimeException("failed to duplicate the X509 certificate")

    val check = crypto.X509_check_purpose(dup, -1, 0)
    // -1 an error condition has occurred, and means
    // the certificate cannot be duplicated or is not valid for some reason.
    if (check < 0) {
      crypto.X509_free(dup)

      crypto.X509_up_ref(cert)
      cert
    } else {
      dup
    }
  }

  private def getX509Alias(cert: X509_*): String = {
    requireNonNull(cert, "the certificate must be non-null")

    val pLen = stackalloc[Int]()
    val cname = crypto.X509_alias_get0(cert, pLen).asInstanceOf[Ptr[Byte]]
    val buffer = stackalloc[Byte](!pLen)
    for (i <- 0 until !pLen)
      !(buffer + i) = (!(cname + i)).toByte
    fromCStringSlice(cname, (!pLen).toCSize, UTF_8)
  }

}
