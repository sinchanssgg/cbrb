simple CRBB
{
    parameters:
        int id;
        int n;
        int t;
        int c;
        int senderId;
        int messageLen;
        bool byzantine = default(false);
        double byzDropRate = default(0.0);
        @display("i=block/routing");

        int byzantineMode = default(0);
        int variant = default(0);
        int equivocateFirst = default(0);
        int helperTarget = default(-1);
        int floodTarget = default(-1);
        int floodCount = default(3000);

    gates:
        input in[];
        output out[];
}
