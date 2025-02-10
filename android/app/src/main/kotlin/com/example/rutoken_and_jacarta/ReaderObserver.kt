package com.signillion.signillion

import ru.rutoken.rttransport.RtTransport

class ReaderObserver(private val rutokenSignAndVerify: RutokenSignAndVerify) :
    RtTransport.PcscReaderObserver {
    override fun onReaderAdded(reader: RtTransport.PcscReader) {
        rutokenSignAndVerify.showUsbDialog("Reader added: ${reader.name}", "")
        rutokenSignAndVerify.handleSlotFromGetSlotList()
    }

    override fun onReaderRemoved(reader: RtTransport.PcscReader) {
        rutokenSignAndVerify.showUsbDialog("Reader removed: ${reader.name}", "")
    }
}
