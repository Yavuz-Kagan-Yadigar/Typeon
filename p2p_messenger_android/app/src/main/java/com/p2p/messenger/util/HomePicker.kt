package com.p2p.messenger.util

import android.content.Context
import android.content.Intent
import android.provider.DocumentsContract
import androidx.activity.result.contract.ActivityResultContracts

/**
 * The system picker reopens the folder it was last in, so after a WhatsApp
 * sticker import every picker started in the WhatsApp folder. These start
 * at the top of the internal storage instead.
 */
private val HOME_URI = DocumentsContract.buildDocumentUri("com.android.externalstorage.documents", "primary:")

class OpenDocumentAtHome : ActivityResultContracts.OpenDocument() {
    override fun createIntent(context: Context, input: Array<String>): Intent =
        super.createIntent(context, input).putExtra(DocumentsContract.EXTRA_INITIAL_URI, HOME_URI)
}

class OpenMultipleDocumentsAtHome : ActivityResultContracts.OpenMultipleDocuments() {
    override fun createIntent(context: Context, input: Array<String>): Intent =
        super.createIntent(context, input).putExtra(DocumentsContract.EXTRA_INITIAL_URI, HOME_URI)
}
