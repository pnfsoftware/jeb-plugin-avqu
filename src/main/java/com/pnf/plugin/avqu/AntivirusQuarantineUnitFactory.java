package com.pnf.plugin.avqu;

import java.nio.ByteBuffer;

import com.pnfsoftware.jeb.core.IUnitCreator;
import com.pnfsoftware.jeb.core.input.IInput;
import com.pnfsoftware.jeb.core.properties.IPropertyDefinitionManager;
import com.pnfsoftware.jeb.core.units.IUnit;
import com.pnfsoftware.jeb.core.units.IUnitProcessor;
import com.pnfsoftware.jeb.util.logging.GlobalLog;
import com.pnfsoftware.jeb.util.logging.ILogger;

/**
 * Factory for anti-virus quarantine units. Refer to {@link AntivirusQuarantinePlugin}.
 * 
 * @author Nicolas Falliere
 *
 */
public class AntivirusQuarantineUnitFactory {
    @SuppressWarnings("unused")
    private static final ILogger logger = GlobalLog.getLogger(AntivirusQuarantineUnitFactory.class);

    public static IUnit create(String name, IInput input, IUnitProcessor unitProcessor, IUnitCreator parent,
            IPropertyDefinitionManager pdm) {

        // Kaspersky KLQ
        ByteBuffer hdr = input.getHeader();
        if(input.getCurrentSize() >= 0x40 || hdr.getLong() == 0x4B4C514201000000L) {
            return new KasperskyQuarantineUnit(name, input, unitProcessor, parent, pdm);
        }

        // others
        // ...

        return null;
    }
}
