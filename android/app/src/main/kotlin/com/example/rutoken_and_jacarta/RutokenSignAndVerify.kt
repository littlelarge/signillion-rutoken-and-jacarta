package com.signillion.signillion

import android.app.AlertDialog
import com.example.rutoken_sample.createobjects.GostKeyPairParams
import com.rutoken_and_jacarta.MainActivity
import org.bouncycastle.asn1.ASN1BitString
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import ru.rutoken.pkcs11jna.Pkcs11Constants.CKO_CERTIFICATE
import ru.rutoken.pkcs11wrapper.attribute.IPkcs11AttributeFactory
import ru.rutoken.pkcs11wrapper.attribute.Pkcs11Attribute
import ru.rutoken.pkcs11wrapper.constant.standard.Pkcs11AttributeType
import ru.rutoken.pkcs11wrapper.constant.standard.Pkcs11AttributeType.CKA_VALUE
import ru.rutoken.pkcs11wrapper.constant.standard.Pkcs11ObjectClass
import ru.rutoken.pkcs11wrapper.constant.standard.Pkcs11UserType
import ru.rutoken.pkcs11wrapper.datatype.Pkcs11KeyPair
import ru.rutoken.pkcs11wrapper.main.Pkcs11Exception
import ru.rutoken.pkcs11wrapper.main.Pkcs11Session
import ru.rutoken.pkcs11wrapper.main.Pkcs11Token
import ru.rutoken.pkcs11wrapper.mechanism.Pkcs11Mechanism
import ru.rutoken.pkcs11wrapper.`object`.Pkcs11StorageObject
import ru.rutoken.pkcs11wrapper.`object`.certificate.Pkcs11CertificateObject
import ru.rutoken.pkcs11wrapper.`object`.key.Pkcs11PrivateKeyObject
import ru.rutoken.pkcs11wrapper.`object`.key.Pkcs11PublicKeyObject
import ru.rutoken.rtpcscbridge.RtPcscBridge
import java.io.ByteArrayInputStream
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

class RutokenSignAndVerify(private val mainActivity: MainActivity) {
    private val DATA_TO_SIGN =
        "Hello Rutoken! This is simple sample of sign hash data".toByteArray(
            Charsets.UTF_8
        )

    /**
     * We will find certificate by its ID. Change this field to your certificate ID.
     * Also change GOST key algorithm by setting field [GOST_KEY_PAIR_PARAMS]
     */
    private val CERTIFICATE_ID = GostKeyPairParams.GOST_2001_256.id
    private val GOST_KEY_PAIR_PARAMS = GostKeyPairParams.GOST_2001_256

    /**
     * Change this flag to false if you want to digest data by yourself.
     */

    /**
     * Change this flag to true if you want to digest data on the CPU and not on the token.
     * This flag is available if [SIGN_WITH_DIGEST] == false.
     */
    private val USE_PROGRAM_HASH = false

    private val module = Module()

    fun initializeRtPcscBridge() {
        val transport = RtPcscBridge.getTransport()
        transport.initialize(mainActivity)
        transport?.addPcscReaderObserver(ReaderObserver(this))
    }

    /*
     * Should be called ONLY if guaranteed that the token is already connected and all permissions
     * is granted. Otherwise, Pkcs11Module#getSlotList returns an empty list
     */
    fun handleSlotFromGetSlotList() {
        try {
            module.initializeModule(null) // resolved the error

            val slots = module.getSlotList(true)
            if (slots.isNotEmpty())
                doPkcs11Operation(slots.first().token)
        } catch (e: Exception) {
            showUsbDialog("Failed to handle slot from get slot list.", e.toString())
        }
    }

    private fun doPkcs11Operation(token: Pkcs11Token) {

        try {
            token.openSession(true).use { session ->
                var signMechanism: Pkcs11Mechanism? = null
                var digestMechanism: Pkcs11Mechanism? = null
                when (GOST_KEY_PAIR_PARAMS) {

                    GostKeyPairParams.GOST_2001_256 -> {
                        signMechanism = Pkcs11Mechanism.make(token.mechanismList[23])
                        digestMechanism = Pkcs11Mechanism.make(token.mechanismList[29])
                    }
                }

                println("Механизм: ${signMechanism.mechanismType}")

                try {
                    session.login(Pkcs11UserType.CKU_USER, "214021").use {
                        try {
                            val allCertificates = session.objectManager.findObjectsAtOnce(
                                Pkcs11CertificateObject::class.java,
                                listOf(
                                    session.attributeFactory.makeAttribute(
                                        Pkcs11AttributeType.CKA_CLASS,
                                        CKO_CERTIFICATE
                                    ),
                                )
                            )

                            showUsbDialog("Finding signer certificate", "")
                            val signerCertificate = allCertificates.first()
                            val signerCertificateValue = signerCertificate
                                .getByteArrayAttributeValue(session, CKA_VALUE)
                                .byteArrayValue

                            val keyPair =
                                findKeyPairByCertificateValue(session, signerCertificateValue)
                            showUsbDialog("Data to sign:", DATA_TO_SIGN.toString())
                            val dataToSign =
                                session.digestManager.digestAtOnce(DATA_TO_SIGN, digestMechanism)

                            val signature = session.signManager.signAtOnce(
                                dataToSign,
                                signMechanism,
                                keyPair.privateKey
                            )
                            showUsbDialog("Signed data:", signature.toString())

                            showUsbDialog("Verifying GOST signature", "")
                            val result = session.verifyManager.verifyAtOnce(
                                dataToSign,
                                signature,
                                signMechanism,
                                keyPair.publicKey
                            )

                            if (result) {
                                showUsbDialog("GOST signature is valid", "")
                            } else {
                                throw IllegalStateException("GOST signature is invalid")
                            }
                        } catch (e: Exception) {
                            showUsbDialog(
                                "Error",
                                "An unexpected error occurred while trying to sign: ${e.message}"
                            )
                        }
                    }
                } catch (e: Pkcs11Exception) {
                    if (e.message?.contains("CKR_PIN_INCORRECT") == true) {
                        showUsbDialog("Error", "Invalid password provided.")
                    } else {
                        showUsbDialog("Error", "An unexpected error occurred: ${e.message}")
                        throw e
                    }
                }
            }
        } catch (e: Exception) {
            println(e)
        } finally {
            module.finalizeModule()
        }
    }

    fun <T : Pkcs11StorageObject> findFirstObject(
        session: Pkcs11Session,
        clazz: Class<T>,
        template: List<Pkcs11Attribute>
    ): T {
        val objects = session.objectManager.findObjectsAtOnce(clazz, template)
        if (objects.isEmpty()) {
            throw IllegalStateException("${clazz.simpleName} object not found")
        }
        return objects[0]
    }

    @Throws(CertificateException::class)
    fun findKeyPairByCertificateValue(
        session: Pkcs11Session,
        certificateValue: ByteArray
    ): Pkcs11KeyPair<Pkcs11PublicKeyObject, Pkcs11PrivateKeyObject> {
        // Find corresponding public key handle for certificate
        val x509certificate = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(certificateValue)) as X509Certificate

        val publicKeyValueTemplate: List<Pkcs11Attribute>
        // GOST
        val sequence = ASN1Sequence.getInstance(x509certificate.publicKey.encoded)
        val publicKeyValue = ASN1OctetString.getInstance(
            (sequence.getObjectAt(1) as ASN1BitString).octets
        ).octets

        publicKeyValueTemplate =
            makeGostPublicKeyBaseTemplate(session.attributeFactory, publicKeyValue)

        // For simplicity, we find first object matching template, in production you should generally check that
        // only single object matches template.
        val publicKey =
            findFirstObject(session, Pkcs11PublicKeyObject::class.java, publicKeyValueTemplate)

        // Using public key we can find private key handle
        val publicKeyId = publicKey.getIdAttributeValue(session).byteArrayValue
        val privateKeyTemplate = makePrivateKeyBaseTemplate(session.attributeFactory, publicKeyId)

        // For simplicity, we find first object matching template, in production you should generally check that
        // only single object matches template.
        val privateKey =
            findFirstObject(session, Pkcs11PrivateKeyObject::class.java, privateKeyTemplate)

        return Pkcs11KeyPair(publicKey, privateKey)
    }

    fun makeGostPublicKeyBaseTemplate(
        attributeFactory: IPkcs11AttributeFactory,
        publicKeyValue: ByteArray
    ): List<Pkcs11Attribute> {
        return listOf(
            attributeFactory.makeAttribute(
                Pkcs11AttributeType.CKA_CLASS,
                Pkcs11ObjectClass.CKO_PUBLIC_KEY
            ),
            attributeFactory.makeAttribute(Pkcs11AttributeType.CKA_VALUE, publicKeyValue)
        )
    }

    fun makePrivateKeyBaseTemplate(
        attributeFactory: IPkcs11AttributeFactory,
        privateKeyId: ByteArray
    ): List<Pkcs11Attribute> {
        return listOf(
            attributeFactory.makeAttribute(
                Pkcs11AttributeType.CKA_CLASS,
                Pkcs11ObjectClass.CKO_PRIVATE_KEY
            ),
            attributeFactory.makeAttribute(Pkcs11AttributeType.CKA_ID, privateKeyId)
        )
    }

    fun showUsbDialog(title: String, message: String) {
        AlertDialog.Builder(mainActivity)
            .setTitle(title)
            .setMessage(message)
            .setPositiveButton("OK") { dialog, _ -> dialog.dismiss() }
            .create()
            .show()
    }
}