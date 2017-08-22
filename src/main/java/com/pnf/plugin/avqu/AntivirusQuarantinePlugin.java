package com.pnf.plugin.avqu;

import com.pnfsoftware.jeb.core.IPluginInformation;
import com.pnfsoftware.jeb.core.IUnitCreator;
import com.pnfsoftware.jeb.core.PluginInformation;
import com.pnfsoftware.jeb.core.Version;
import com.pnfsoftware.jeb.core.input.IInput;
import com.pnfsoftware.jeb.core.units.AbstractUnitIdentifier;
import com.pnfsoftware.jeb.core.units.IUnit;
import com.pnfsoftware.jeb.core.units.IUnitProcessor;

/**
 * JEB2 plugin to extract files quarantined by anti-virus/security products.
 * <p>
 * Current support:
 * <ul>
 * <li>Kaspersky Anti-Virus KLQ Parser - Some documentation can be found on the
 * <a href="http://www.forensicswiki.org/wiki/Kaspersky_Quarantine_File">Forensics Wiki</a></li>
 * </ul>
 * 
 * @author Nicolas Falliere
 *
 */
public class AntivirusQuarantinePlugin extends AbstractUnitIdentifier {
    public static final String TYPE = "avqu";

    public AntivirusQuarantinePlugin() {
        super(TYPE, 0);
    }

    @Override
    public IPluginInformation getPluginInformation() {
        return new PluginInformation("Antivirus Quarantined File",
                "AV quarantine file extractor. Support: for Kaspersky KLQ", "PNF Software", Version.create(0, 1, 1),
                Version.create(2, 3, 3), null);
    }

    @Override
    public boolean canIdentify(IInput input, IUnitCreator parent) {
        // Kaspersky KLQ
        return checkBytes(input, 0, "KLQB");
    }

    @Override
    public IUnit prepare(String name, IInput input, IUnitProcessor unitProcessor, IUnitCreator parent) {
        IUnit unit = AntivirusQuarantineUnitFactory.create(name, input, unitProcessor, parent,
                getPropertyDefinitionManager());
        unit.process();
        return unit;
    }
}
