package nl.trusttech.constants;

import org.multipaz.cbor.Cbor;
import org.multipaz.cbor.DataItem;
import org.multipaz.cbor.Nint;
import org.multipaz.cbor.Uint;

public class CborConstants {
    public static final Nint N_INT_MINUS_2 = Nint.Companion.decode$multipaz(new byte[]{0x21}, 0).getSecond();
    public static final Nint N_INT_MINUS_3 = Nint.Companion.decode$multipaz(new byte[]{0x22}, 0).getSecond();
    public static final Uint U_INT_33 = Uint.Companion.decode$multipaz(new byte[]{0x18, 0x21}, 0).getSecond();
    public static final DataItem NULL = Cbor.INSTANCE.decode(new byte[]{(byte) 0xf6});
}
