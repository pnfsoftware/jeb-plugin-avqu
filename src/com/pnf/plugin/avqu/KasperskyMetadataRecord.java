package com.pnf.plugin.avqu;

import com.pnfsoftware.jeb.util.serialization.annotations.Ser;
import com.pnfsoftware.jeb.util.serialization.annotations.SerId;

/**
 * Record of quarantined file metadata stored in an encrypted Kaspersky KLQ file.
 * 
 * @author Nicolas Falliere
 *
 */
@Ser
public class KasperskyMetadataRecord {
    @SerId(1)
    private String name;
    @SerId(2)
    private byte[] payload;
    @SerId(3)
    private String representation;

    /**
     * Create a record.
     * 
     * @param name mandatory
     * @param payload mandatory
     * @param representation optional string representation
     */
    public KasperskyMetadataRecord(String name, byte[] payload, String representation) {
        if(name == null || payload == null) {
            throw new IllegalArgumentException();
        }
        this.name = name;
        this.payload = payload;
        this.representation = representation;
    }

    public String getName() {
        return name;
    }

    public String getRepresentation() {
        return representation;
    }

    public byte[] getPayload() {
        return payload;
    }
}