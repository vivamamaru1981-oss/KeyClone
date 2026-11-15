package com.example.keyclone

import android.app.PendingIntent
import android.content.Intent
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.MifareClassic
import android.os.Build
import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.io.File

class MainActivity : AppCompatActivity() {

    private var nfcAdapter: NfcAdapter? = null
    private lateinit var status: TextView
    private var savedDump: ByteArray? = null
    private val savedKeys = mutableMapOf<Int, ByteArray>()

    // Стандартные ключи, которые часто стоят по умолчанию
    private val commonKeys = listOf(
        "FFFFFFFFFFFF", "A0A1A2A3A4A5", "D3F7D3F7D3F7", "000000000000",
        "B0B1B2B3B4B5", "4D3A99C351DD", "1A982C7E459A", "AABBCCDDEEFF",
        "714C5C886E09", "587EE2F93434"
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        status = findViewById(R.id.status)
        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        if (nfcAdapter == null) status.text = "В этом телефоне нет NFC."
    }

    override fun onResume() {
        super.onResume()
        val intent = Intent(this, javaClass).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
        var flags = PendingIntent.FLAG_UPDATE_CURRENT
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            flags = flags or PendingIntent.FLAG_MUTABLE
        }
        val pi = PendingIntent.getActivity(this, 0, intent, flags)
        nfcAdapter?.enableForegroundDispatch(this, pi, null, null)
    }

    override fun onPause() {
        nfcAdapter?.disableForegroundDispatch(this)
        super.onPause()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (intent.action != NfcAdapter.ACTION_TAG_DISCOVERED) return
        @Suppress("DEPRECATION")
        val tag: Tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG) ?: return
        val mfc = MifareClassic.get(tag) ?: run {
            status.text = "Это не MIFARE Classic — такой ключ так не скопировать."
            return
        }
        try {
            mfc.connect()
            if (savedDump == null) readTag(mfc) else writeTag(mfc)
            mfc.close()
        } catch (e: Exception) {
            status.text = "Ошибка: ${e.message}"
        }
    }

    // ---------- ЧТЕНИЕ ОРИГИНАЛА ----------
    private fun readTag(mfc: MifareClassic) {
        val dump = ByteArray(mfc.size)
        val sb = StringBuilder()
        for (sector in 0 until mfc.sectorCount) {
            var authed = false
            for (k in commonKeys) {
                val key = parseKey(k)
                if (mfc.authenticateSectorWithKeyA(sector, key) ||
                    mfc.authenticateSectorWithKeyB(sector, key)
                ) { savedKeys[sector] = key; authed = true; break }
            }
            if (!authed) { sb.append("Сектор $sector: ключ не найден\n"); continue }

            val first = mfc.sectorToBlock(sector)
            for (i in 0 until mfc.getBlockCountInSector(sector)) {
                val block = first + i
                val data = mfc.readBlock(block)
                System.arraycopy(data, 0, dump, block * 16, 16)
                sb.append("Блок $block: ").append(data.toHex()).append('\n')
            }
        }
        File(filesDir, "dump_${System.currentTimeMillis()}.bin").writeBytes(dump)
        savedDump = dump
        sb.append("\nДамп сохранён. Теперь поднесите ЗАГОТОВКУ.")
        status.text = sb.toString()
    }

    // ---------- ЗАПИСЬ КОПИИ ----------
    private fun writeTag(mfc: MifareClassic) {
        val dump = savedDump ?: return
        if (mfc.size != dump.size) {
            status.text = "Заготовка другого объёма (${mfc.size} байт вместо ${dump.size}). " +
                "Нужна карта того же типа и объёма."
            return
        }
        val sb = StringBuilder("Запись:\n")
        for (sector in 0 until mfc.sectorCount) {
            val key = savedKeys[sector] ?: continue
            if (!mfc.authenticateSectorWithKeyA(sector, key)) {
                sb.append("Сектор $sector: не открылся\n"); continue
            }
            val first = mfc.sectorToBlock(sector)
            for (i in 0 until mfc.getBlockCountInSector(sector)) {
                val block = first + i
                val chunk = dump.copyOfRange(block * 16, block * 16 + 16)
                try {
                    mfc.writeBlock(block, chunk)
                    sb.append("Блок $block: ok\n")
                } catch (e: Exception) {
                    sb.append("Блок $block: не записан\n")
                }
            }
        }
        sb.append("\nГотово. Проверьте копию у домофона.")
        status.text = sb.toString()
        savedDump = null
    }

    private fun parseKey(hex: String): ByteArray {
        val out = ByteArray(6)
        for (i in 0 until 6) out[i] = hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        return out
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02X".format(it) }
}
