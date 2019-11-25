'''
n = 22752894188316360092540975721906836497991847739424447868959786578153887300450204451741779348632585992639813683087014583667437383610183725778340014971884694702424840759289252997193997614461702362265455177683286566007629947557111478254578643051667900283702126832059297887141543875571396701604215946728406574474496523342528156416445367009267837915658813685925782997542357007012092288854590169727090121416037455857985211971777796742820802720844285182550822546485833511721384166383556717318973404935286135274368441649494487024480611465888320197131493458343887388661805459986546580104914535886977559349182684565216141697843
p0 = 165268930359949857026074503377557908247892339573941373503738312676595180929705525120390798235341002232499096629250002305840384250879180463692771724228098578839654230711801010511101603925719055251331144950208399022480638167824839670035053131870941541955431984347563680229468562579668449565647313503239028017367

p_part1 = p0 & (2**444-1)
p_part2 = (p0 >> (444+28*8)) << (444+28*8)
F.<x> = PolynomialRing(Zmod(n), implementation='NTL')

f = p_part1 + x*2**444 + p_part2

p_part3 = f.monic().small_roots(beta=0.4, X=2**224)[0]

known = (p0 >> 444) & (2**224-1)
print hex(known ^^ p_part3.lift()).decode("hex")
'''

n = 21449895719826316652446571946981952001870566997635249354839719104586793422147136850745824964669880149217071660375357131860682282796961273035757913027221984662855086934378108862417739678560641256025021177459341664799202908015371506818482697948776860635401930560813387486994329880316276005206046676604369818653109492798511157267685062757615124902736832428778894091595763452172598515654092085157566254905703036750059426372678012021690115369113601765685996153603249713637184151546264425226874180985930269362876845015270912918849008772950078638461376666258348157307814840090503490728994671500681702766815576953787813978261
e1 = 154876861410030193905637296965209391737518615267603515377282161163927291285967965497209788803884091512203071770629845496583933653022795932154979438702329298506942119286672966860218225280626597363420844895229952830077688654634909597435821159150203935892844897371875699700527646518533561853297444882053983227593488765684563676352563626896826395039059975553220690136832152388058883795799274080376167383757159656303732365134738082284498670076819991548527840704114978992615193815662908944493989239004523225764813567930483040425975604255002646785221221878939420219915361396619167751523362930788604016988652824182040859853
e2 = 402990417892531977850271294939175215561881274701367217938141276378027299932263277333257773304557909966758931404723788571151364295341508924840669170504985457120360059297598604537100046622550945605718236227573083837228605402001910225151380616962871923554321544941879414420770210243790557120014475150848993651449636282584509883109795086026235707304394495245201159365863786851663410631339564797425347542642297764418117149471025357391362626205617684148715868071334593025123520727806776519925478240637301296453177836917692916152818769174676318043128314246927769799960281108858830520315473333109470979129926160732972172081

m1 = 1 << 1024
m2 = 1 << (2048+700)
mat = [[n, -m1*n, 0, n^2], [0, m1*e1, -m2*e1, -e1*n], [0, 0, m2*e2, -e2*n], [0,0,0,e1*e2]]
L = matrix(mat)

B = L.LLL()
ans = B[0]*(~L)

k1 = -ans[0]
d1 = -ans[1]
kk = gcd(k1, d1)
d = d1 / kk

m = 42
c = pow(m, e1, n)
tmp = pow(c, d, n)
i = 1
while parent(pow(tmp, i, n).lift().log(m)) != ZZ:
    i+=1
tmp = pow(tmp, i, n).lift().log(m)
d = d / tmp
p = 1
q = 1
while p==1 and q==1:
    k = d * e1 - 1
    g = randint(0, n)
    while p==1 and q==1 and k % 2 == 0:
        k /= 2
        y = pow(int(g), int(k), int(n))
        if y !=1 and gcd(y-1, n) > 1:
            p = gcd(y-1, n)
            q = n / p

assert p * q == n

phi = (p-1)*(q-1)
d = inverse_mod(65537, phi)
c = 21037638775241935705441169753441969181214988969805330775013543248627632552311198450678114235819562675518919466977321520345880402152065754456138008928612618730995007509860931974158286638375767596664571588900873546529219194178268112698039853957041774843749061288696704191382908696861582667493389648259168539280602684104107043926115007135814623174879703368347247535365452080470946340175647350659950178146229633608967125085585415972497659100238875587736956198682668140956431794164348384880775647438732698709407480919045992477653549924142632962331437675488780736097081752111600358026119501809787360220615860538667734006333

m = pow(c, d, n).lift()
print hex(m).decode("hex")