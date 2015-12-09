package com.pnf.plugin.avqu;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.List;

import com.pnfsoftware.jeb.core.IUnitCreator;
import com.pnfsoftware.jeb.core.input.BytesInput;
import com.pnfsoftware.jeb.core.input.IInput;
import com.pnfsoftware.jeb.core.input.SubInput;
import com.pnfsoftware.jeb.core.output.AbstractUnitRepresentation;
import com.pnfsoftware.jeb.core.output.IGenericDocument;
import com.pnfsoftware.jeb.core.output.IUnitFormatter;
import com.pnfsoftware.jeb.core.output.UnitFormatterUtil;
import com.pnfsoftware.jeb.core.output.table.ITableDocument;
import com.pnfsoftware.jeb.core.output.table.ITableRow;
import com.pnfsoftware.jeb.core.output.table.impl.Cell;
import com.pnfsoftware.jeb.core.output.table.impl.StaticTableDocument;
import com.pnfsoftware.jeb.core.output.table.impl.TableRow;
import com.pnfsoftware.jeb.core.properties.IPropertyDefinitionManager;
import com.pnfsoftware.jeb.core.units.AbstractBinaryUnit;
import com.pnfsoftware.jeb.core.units.IUnitProcessor;
import com.pnfsoftware.jeb.util.Formatter;
import com.pnfsoftware.jeb.util.IO;
import com.pnfsoftware.jeb.util.Strings;
import com.pnfsoftware.jeb.util.logging.GlobalLog;
import com.pnfsoftware.jeb.util.logging.ILogger;
import com.pnfsoftware.jeb.util.serialization.annotations.Ser;
import com.pnfsoftware.jeb.util.serialization.annotations.SerConstructor;
import com.pnfsoftware.jeb.util.serialization.annotations.SerId;

/**
 * Decryptor and extractor for Kaspersky KLQ quarantined files. Those units are produced by the
 * {@link AntivirusQuarantineUnitFactory}.
 * 
 * @author Nicolas Falliere
 *
 */
@Ser
public class KasperskyQuarantineUnit extends AbstractBinaryUnit {
    public static final ILogger logger = GlobalLog.getLogger(KasperskyQuarantineUnit.class);

    @SerId(1)
    private List<KasperskyMetadataRecord> metadataRecords = new ArrayList<>();

    @SerConstructor
    KasperskyQuarantineUnit() {
    }

    public KasperskyQuarantineUnit(String name, IInput input, IUnitProcessor unitProcessor, IUnitCreator parent,
            IPropertyDefinitionManager pdm) {
        super(null, input, AntivirusQuarantinePlugin.TYPE, name, unitProcessor, parent, pdm);
    }

    @Override
    public boolean process() {
        if(isProcessed()) {
            return true;
        }

        try {
            IInput input = getInput();

            // Kaspersky KLQ
            ByteBuffer hdr = input.getHeader();
            if(input.getCurrentSize() < 0x40 || hdr.getLong() != 0x4B4C514201000000L) {
                logger.info("This file does not appear to be a valid Kaspersky  Quarantine file");
                return false;
            }

            byte[] data = IO.readInputStream(input.getStream());
            ByteBuffer b = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);

            // 64-byte header
            b.position(8);
            int offsetOriginalData = b.getInt();
            b.getInt();
            int offsetMetadata = b.getInt();
            b.position(32);
            int sizeMetadata = b.getInt();
            b.position(48);
            int sizeOriginalData = b.getInt();

            // decrypt the quarantined file
            final byte[] key1 = {(byte)0xE2, 0x45, 0x48, (byte)0xEC, 0x69, 0x0E, 0x5C, (byte)0xAC};
            applyByteXor(data, offsetOriginalData, sizeOriginalData, key1, 0);

            // decrypt the metadata chunks
            final byte[] key2 = {0x48, (byte)0xEC, 0x69, 0x0E, 0x5C, (byte)0xAC, (byte)0xE2, 0x45};
            int offset = offsetMetadata;
            while(offset < offsetMetadata + sizeMetadata) {
                int recordSize = b.getInt(offset);
                offset += 4;
                applyByteXor(data, offset, recordSize, key2, 6);
                parseRecord(data, offset, recordSize);
                offset += recordSize;
            }

            // find the name of the quarantined file
            String filename = null;
            KasperskyMetadataRecord r = getMetadataRecordByName("cNP_QB_FULLNAME");
            if(r != null) {
                filename = extractSimpleFilename(r.getRepresentation());
            }
            filename = Strings.safe(filename, "Quarantined Data");

            BytesInput input2 = new BytesInput(data);
            addChildUnit(getUnitProcessor().process(filename,
                    new SubInput(input2, offsetOriginalData, sizeOriginalData), this));
        }
        catch(IOException e) {
            logger.catching(e);
            return false;
        }
        // example, array out of bound when reading the ByteBuffer
        catch(RuntimeException e) {
            logger.catching(e);
            return false;
        }

        setProcessed(true);
        return true;
    }

    String extractSimpleFilename(String s) {
        int pos = s.lastIndexOf('/');
        if(pos < 0) {
            pos = s.lastIndexOf('\\');
        }
        if(pos < 0) {
            return s;
        }
        return s.substring(pos + 1);
    }

    public List<KasperskyMetadataRecord> getMetadataRecords() {
        return Collections.unmodifiableList(metadataRecords);
    }

    public KasperskyMetadataRecord getMetadataRecordByName(String name) {
        for(KasperskyMetadataRecord r: metadataRecords) {
            if(Strings.equals(r.getName(), name)) {
                return r;
            }
        }
        return null;
    }

    void applyByteXor(byte[] data, int pos, int size, byte[] key, int keystart) {
        int j = keystart % key.length;
        for(int i = pos; i < pos + size; i++) {
            data[i] ^= key[j];
            j = (j + 1) % key.length;
        }
    }

    void parseRecord(byte[] data, int offset, int size) {
        ByteBuffer b = ByteBuffer.wrap(data, offset, size).order(ByteOrder.LITTLE_ENDIAN);
        int nameSize = b.getInt();
        byte[] nameBytes = new byte[nameSize];
        b.get(nameBytes);
        String name = new String(nameBytes, 0, nameSize - 1);
        logger.i("Name: %s", name);

        String representation = null;
        switch(name) {
        case "cNP_QB_ID": {
            long v = b.getLong();
            representation = String.format("%Xh", v);
            break;
        }
        case "cNP_QB_FULLNAME": {
            representation = new String(data, offset + 4 + nameSize, size - 4 - nameSize, Charset.forName("UTF-16LE"));
            break;
        }
        case "cNP_QB_RESTORER_PID":
        case "cNP_QB_FILE_ATTRIBUTES": {
            int v = b.getInt();
            representation = String.format("%Xh", v);
            break;
        }
        case "cNP_QB_FILE_CREATION_TIME":
        case "cNP_QB_FILE_LAST_ACCESS_TIME":
        case "cNP_QB_FILE_LAST_WRITE_TIME":
        case "cNP_QB_STORE_TIME": {
            long v = b.getLong();
            Calendar c = Calendar.getInstance();
            c.clear();
            c.set(1, 0, 1);
            c.add(Calendar.DAY_OF_MONTH, (int)(v / 8640000000000L));
            v %= 8640000000000L;
            c.add(Calendar.MILLISECOND, (int)(v / 100000L));
            representation = c.getTime().toString();
            break;
        }
        case "cNP_QB_INFO": {
            // TODO: parse
            break;
        }
        default:
            ;
        }

        KasperskyMetadataRecord record = new KasperskyMetadataRecord(name, Arrays.copyOfRange(data, offset + 4
                + nameSize, offset + size), representation);

        metadataRecords.add(record);
    }

    ITableDocument constructMetadataTableDoc() {
        List<String> labels = Arrays.asList("Name", "Info", "Raw");
        List<ITableRow> rows = new ArrayList<>();
        for(KasperskyMetadataRecord r: metadataRecords) {
            rows.add(new TableRow(new Cell(r.getName()), new Cell(r.getRepresentation() != null ? r.getRepresentation()
                    : formatBytes(r.getPayload())), new Cell(Formatter.byteArrayToHexString(r.getPayload()))));
        }
        return new StaticTableDocument(labels, rows);
    }

    String formatBytes(byte[] data) {
        return formatBytes(data, 0, data.length);
    }

    String formatBytes(byte[] data, int offset, int size) {
        StringBuilder sb = new StringBuilder();
        for(int i = 0; i < size; i++) {
            byte b = data[offset + i];
            if(b >= 0x20 && b < 0x7F) {
                sb.append((char)b);
            }
            else {
                sb.append('.');
            }
        }
        return sb.toString();
    }

    @Override
    public IUnitFormatter getFormatter() {
        IUnitFormatter formatter = super.getFormatter();
        if(UnitFormatterUtil.getPresentationByIdentifier(formatter, 1) == null) {
            final ITableDocument metadataTable = constructMetadataTableDoc();
            formatter.addPresentation(new AbstractUnitRepresentation(1, "Metadata", true) {
                @Override
                public IGenericDocument getDocument() {
                    return metadataTable;
                }
            }, false);
        }

        return formatter;
    }

    @Override
    public byte[] getIconData() {
        try {
            return IO.readInputStream(getClass().getResourceAsStream("kav.png"));
        }
        catch(IOException e) {
            return null;
        }
    }
}
