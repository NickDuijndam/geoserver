/* (c) 2017 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.wms.map;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;

import java.io.InputStream;
import org.apache.commons.io.output.NullOutputStream;
import org.geoserver.wms.WMSMapContent;
import org.junit.Test;

public class RawMapTest {

    @Test
    @SuppressWarnings("PMD.CloseResource")
    public void testInputStream() throws Exception {
        InputStream stream = createMock(InputStream.class);
        expect(stream.read(anyObject())).andReturn(-1).once();
        replay(stream);

        WMSMapContent map = createNiceMock(WMSMapContent.class);
        replay(map);

        new RawMap(map, stream, "text/plain").writeTo(NullOutputStream.INSTANCE);
        verify(stream);
    }
}
