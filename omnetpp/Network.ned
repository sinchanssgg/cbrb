network Network
{
    parameters:
        int n = default(7);
        int t = default(2);
        int c = default(1);
        int senderId = default(0);
        int messageLen = default(32);

    submodules:
        node[n]: CRBB {
            parameters:
                id = index;
                n = parent.n;
                t = parent.t;
                c = parent.c;
                senderId = parent.senderId;
                messageLen = parent.messageLen;
        }

    connections allowunconnected:
        node[0].out[1] --> node[1].in[0];
        node[0].out[2] --> node[2].in[0];
        node[0].out[3] --> node[3].in[0];
        node[0].out[4] --> node[4].in[0];
        node[0].out[5] --> node[5].in[0];
        node[0].out[6] --> node[6].in[0];
        node[1].out[0] --> node[0].in[1];
        node[1].out[2] --> node[2].in[1];
        node[1].out[3] --> node[3].in[1];
        node[1].out[4] --> node[4].in[1];
        node[1].out[5] --> node[5].in[1];
        node[1].out[6] --> node[6].in[1];
        node[2].out[0] --> node[0].in[2];
        node[2].out[1] --> node[1].in[2];
        node[2].out[3] --> node[3].in[2];
        node[2].out[4] --> node[4].in[2];
        node[2].out[5] --> node[5].in[2];
        node[2].out[6] --> node[6].in[2];
        node[3].out[0] --> node[0].in[3];
        node[3].out[1] --> node[1].in[3];
        node[3].out[2] --> node[2].in[3];
        node[3].out[4] --> node[4].in[3];
        node[3].out[5] --> node[5].in[3];
        node[3].out[6] --> node[6].in[3];
        node[4].out[0] --> node[0].in[4];
        node[4].out[1] --> node[1].in[4];
        node[4].out[2] --> node[2].in[4];
        node[4].out[3] --> node[3].in[4];
        node[4].out[5] --> node[5].in[4];
        node[4].out[6] --> node[6].in[4];
        node[5].out[0] --> node[0].in[5];
        node[5].out[1] --> node[1].in[5];
        node[5].out[2] --> node[2].in[5];
        node[5].out[3] --> node[3].in[5];
        node[5].out[4] --> node[4].in[5];
        node[5].out[6] --> node[6].in[5];
        node[6].out[0] --> node[0].in[6];
        node[6].out[1] --> node[1].in[6];
        node[6].out[2] --> node[2].in[6];
        node[6].out[3] --> node[3].in[6];
        node[6].out[4] --> node[4].in[6];
        node[6].out[5] --> node[5].in[6];
}
