// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Collections;
import java.util.Objects;
import java.util.regex.Pattern;

public final class Main {
    private static final String TESTS_METHODS_PREFIX = "test";
    private static final Pattern CAMEL_CASE_SPLITTER =
            Pattern.compile("(?=[A-Z][a-z])");
    private static final String SEPARATOR = System.lineSeparator() +
            String.join("", Collections.nCopies(160, "#"));
    private static final String CFG_NAME_SUFFIX = "NSS-Adapter-Test";
    private static final String PROVIDER = "SunPKCS11-" + CFG_NAME_SUFFIX;

    private static void initialize(String nssAdapterLib) throws Exception {
        // Find the NSS adapter library
        FileSystem fs = FileSystems.getDefault();
        Path lib = fs.getPath(nssAdapterLib);
        if (!Files.isRegularFile(lib) || !Files.isReadable(lib)) {
            throw new Exception("Unable to read library file: " + lib);
        }

        // Check for system FIPS
        Path fipsEnabledPath = fs.getPath("/proc/sys/crypto/fips_enabled");
        if (Files.readAllBytes(fipsEnabledPath)[0] != '1') {
            throw new Exception("The system must be in FIPS mode");
        }

        // Check for the old importer/exporter
        try {
            Class.forName("sun.security.pkcs11.FIPSKeyImporter");
            throw new Exception("Java (old) importer/exporter detected, " +
                    "please use a vanilla or newer JDK");
        } catch (ClassNotFoundException ignored) {
            // The test can continue
        }

        // Create a SunPKCS11 inline configuration
        String lf = "\\n";
        String cfg = "--"
                + lf + "name = " + CFG_NAME_SUFFIX
                + lf + "library = " + lib.toRealPath()
                + lf + "slot = 3"
                + lf + "nssUseSecmod = false"
                + lf + "attributes(*,CKO_SECRET_KEY,CKK_GENERIC_SECRET)=" +
                "{ CKA_SIGN=true }";

        // Set our custom provider list with SunPKCS11 as the first one
        int n = 1;
        String SunPKCS11 = "SunPKCS11";
        String SunEC = "SunEC";
        if (System.getProperty("java.version").startsWith("1.")) {
            SunPKCS11 = "sun.security.pkcs11." + SunPKCS11;
            SunEC = "sun.security.ec." + SunEC;
        }
        Security.setProperty("security.provider." + n++, SunPKCS11 + " " + cfg);
        Security.setProperty("security.provider." + n++, SunEC);
        // Clear any other provider from the list
        while (Security.getProperty("security.provider." + n) != null) {
            Security.setProperty("security.provider." + n++, "");
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            throw new Exception("A *.so library program argument is required");
        }
        initialize(args[0]);
        for (Method method : Main.class.getDeclaredMethods()) {
            if (method.getName().startsWith(TESTS_METHODS_PREFIX)) {
                System.out.println(SEPARATOR);
                method.invoke(null);
                succeed(getDescription(method));
            }
        }
        System.out.println(SEPARATOR);
        succeed("TEST PASS");
    }

    private static String getDescription(Method method) {
        String desc = method.getName().substring(TESTS_METHODS_PREFIX.length());
        StringBuilder sb = new StringBuilder();
        for (String word : CAMEL_CASE_SPLITTER.split(desc)) {
            sb.append(word).append(' ');
        }
        sb.deleteCharAt(sb.length() - 1);
        return sb.toString();
    }

    private static void succeed(String m) {
        String line = String.join("", Collections.nCopies(m.length() + 5, "_"));
        System.out.println(line + System.lineSeparator() + m + " - OK");
    }

    private static void assertEquals(Object expected, Object actual,
            String repr) throws Exception {
        if (!Objects.equals(actual, expected)) {
            throw new Exception("Unexpected " + repr + " (found: " + actual +
                    ", but was expecting: " + expected + ")");
        }
    }

    private static void ensureKeyIsFromSunPKCS11(Object key) throws Exception {
        if (!key.getClass().toString().contains(".P11Key$")) {
            throw new Exception("Unexpected key: " + key.getClass());
        }
    }

    private static void testSecretKeyImportAndExport() throws Exception {
        BigInteger rawKey = new BigInteger("331609782999261118064459749711703" +
                "22140116389299700518577411521037425918595095");

        SecretKeyFactory skf = SecretKeyFactory.getInstance("AES", PROVIDER);
        SecretKey key = skf.translateKey(
                new SecretKeySpec(rawKey.toByteArray(), "AES"));

        ensureKeyIsFromSunPKCS11(key);
        byte[] exported = key.getEncoded();
        Objects.requireNonNull(exported, "Could not export secret key");
        assertEquals(rawKey, new BigInteger(exported), "key bytes");
    }

    private static void testSecretKeyGenerateAndExport() throws Exception {
        int keyBytes = 32;

        KeyGenerator kg = KeyGenerator.getInstance("AES", PROVIDER);
        kg.init(keyBytes << 3);
        SecretKey key = kg.generateKey();

        ensureKeyIsFromSunPKCS11(key);
        byte[] exported = key.getEncoded();
        Objects.requireNonNull(exported, "Could not export secret key");
        assertEquals(keyBytes, exported.length, "key length");
    }

    private static void testRSAPrivateKeyImportAndExport() throws Exception {
        BigInteger modulus = new BigInteger("84737273339079744212016956420604" +
                "672536560539844521012747087624164213633972673792142257314988" +
                "038212488382133403829735253956331337879327787540424241875447" +
                "110626308190517297888819820211494106132233241539968974645628" +
                "291367685074471517226859251119924455947021493844558983433614" +
                "394733681765838096812255258199223381056599871026789450943739" +
                "434756825933472898084578552083276903227684134180989326969899" +
                "824540251787930696923292469915471741838554996987042544758006" +
                "887668420366047939313285525049456990185189778495558666660543" +
                "852386658010268346850215209136801304753565477930128140812467" +
                "818658359201430958393836109415503457683628860048116031085371" +
                "281329199067678468158907778216916103114384686372707077964991" +
                "406089070496304759019508271671224973679590022487362128061432" +
                "804142136144312843855402928790362212817502916616829853658682" +
                "592949579769926344959964195803606132747178409912517328672189" +
                "369184672376792426727834704568528674595882544679607222432209" +
                "688077310454874712083104083067980125196465224805804021563223" +
                "741233489051626935181270685123926502849230621322985031078377" +
                "805808050598793297034863612240750587979502382128427340390266" +
                "106800623888931334804620346624238116441976848046605804088632" +
                "262190446351789589095583047633442439688338729573579427363295" +
                "9");
        BigInteger publicExponent = new BigInteger("65537");
        BigInteger privateExponent = new BigInteger("163101505185745675475302" +
                "179954486418620388929897418300394912314420781068060529708558" +
                "296061753911230516303221359325296452543165183282539691461110" +
                "761728157769961329427541763312101198110669149000573145765893" +
                "866162210366885524722205922464900136297402543531700052505026" +
                "061083560245718911246343999914276508621710383499165215537396" +
                "513256603308015316651325796555825891519980544694694830496679" +
                "717573554074288265587202919929028314043779588236027283747051" +
                "006431462820161632163131014612728726633256817170617584087191" +
                "174541012012440529391111900352783886301811199599287688076903" +
                "341971539023523486297274947687420175202079492035054424437390" +
                "435778501949283788537644163415572082676900309518058226962051" +
                "257331321835348753085682967531304163658554538224331863867769" +
                "357200369923911678548598964773798707272931169500371907487079" +
                "148653255243411226909603825498822796832628267190844208943213" +
                "137814579998814890151745599440358768049842010248669628491727" +
                "124641959858806316849845458330324214959945890078514991622453" +
                "947251523402879078357859091345247029970109238994810046393964" +
                "404548184101457126570159231802522721692802948390875184426702" +
                "096742898696650300705393991004130353809620872144187329275264" +
                "204697432626318398194632991721488079754197807097265450149758" +
                "828735073");
        BigInteger prime1 = new BigInteger("313436523421654668161626083201773" +
                "456874278833060065750663048643278662310496370367281574920058" +
                "857328913902753289332681441789219785207918381774786124764775" +
                "518210133617472004039249302448515618804638630937345824674117" +
                "968407085967108594344435020377726693728927691479048233162399" +
                "950605153629869004384234410967957954616997977917317778888492" +
                "984125568121797658123434890569999433281889289598567713440738" +
                "160592166282746495547440238550356514265419607714537257004485" +
                "723193390864564291041554207242024836308270463494928342214882" +
                "950632513343077812957594167644894492099398641779875847967252" +
                "85746274839518848001612880533944158409671201");
        BigInteger prime2 = new BigInteger("270349072322646317238556379044621" +
                "428487070487782509256256824710459639721428003803596832293829" +
                "274120441962541399741957938308577428539331844056685663165632" +
                "610339833938684919564792103644194592241765211307834850027735" +
                "353768453169302628350484685989472274928093354613519083097086" +
                "607768080526153472789835541987883919818018049539912186581282" +
                "871539504994679712438087538996901659872076202163620497014268" +
                "751253674592283556777989489711775715759161332359552749540565" +
                "511354897814755742326380741453379413990426089012102410601191" +
                "598886803813601717821160094908616228875277227008411434576514" +
                "50391595013497104661651775475853648281512159");
        BigInteger primeExponent1 = new BigInteger("1652958347574534788135270" +
                "257658985644214539119615178063447562019774650468494980336906" +
                "753801222855333921648375602471296518168212493149835224514420" +
                "563059061516453093380390833209413673379250929570459490433884" +
                "125362293852951112378535367461489414269037335956665528312077" +
                "915461322168060075950307845877582085215155229484517770538525" +
                "882164898380662509029337726789776261940632072430635767140042" +
                "618969252835251300954313499108996372244292818719415365645335" +
                "715182116295376653655350569445991807787793520070562241071717" +
                "253403540677748588761074716792097536070134952155181936493289" +
                "1431472592977444054556211371160479988619833116484673");
        BigInteger primeExponent2 = new BigInteger("1339019315439080131462157" +
                "264413752776094466947437363696552562690010208791606726500259" +
                "880107069020240405588307953617644182293425596287091514423915" +
                "746274079456128753169921187889764817475709364811892329379178" +
                "056960234613016157266210433229585258284369141731527273258591" +
                "244233247064734713807306060203863724754979940688903350483780" +
                "090090855853971395109221274354993593823249138570211258103227" +
                "388053033197383810254592711447508863091725244295951424140726" +
                "955778683262672991297583257688682556048750442975606275742381" +
                "288144815798688626545235784438539554867278451758777299646464" +
                "6179034226157913455576483777365711459880821874939113");
        BigInteger coefficient = new BigInteger("1354816459695399149365753073" +
                "221412196042443849435764511030939739132881725715692190511424" +
                "555464787786311856241098788850514086508847327138444895237906" +
                "807596349225333013049446688138670369527667008309680207211183" +
                "013371884902570697379832252296024563734045797960734968614180" +
                "208685771091500511279579443560187128384139310217632488211257" +
                "589667489276577695202443087815250717278048805976325869117621" +
                "144779866225326137020408107998612608240076123265449438442165" +
                "747556568532542348215252863022057164112413872375575206551738" +
                "034274565916208513555718393838069574194332902700471898985854" +
                "7682512137336306770008811024491441058352227056724");

        KeyFactory kf = KeyFactory.getInstance("RSA", PROVIDER);
        PrivateKey pk = kf.generatePrivate(
                new RSAPrivateCrtKeySpec(modulus, publicExponent,
                        privateExponent, prime1, prime2, primeExponent1,
                        primeExponent2, coefficient));

        ensureKeyIsFromSunPKCS11(pk);
        Objects.requireNonNull(pk.getEncoded(), "Could not export private key");
        RSAPrivateCrtKey rsaPk = (RSAPrivateCrtKey) pk;
        assertEquals(modulus, rsaPk.getModulus(), "modulus");
        assertEquals(publicExponent, rsaPk.getPublicExponent(),
                "publicExponent");
        assertEquals(privateExponent, rsaPk.getPrivateExponent(),
                "privateExponent");
        assertEquals(prime1, rsaPk.getPrimeP(), "prime1 (primeP)");
        assertEquals(prime2, rsaPk.getPrimeQ(), "prime2 (primeQ)");
        assertEquals(primeExponent1, rsaPk.getPrimeExponentP(),
                "primeExponent1 (primeExponentP)");
        assertEquals(primeExponent2, rsaPk.getPrimeExponentQ(),
                "primeExponent2 (primeExponentQ)");
        assertEquals(coefficient, rsaPk.getCrtCoefficient(), "coefficient");
    }

    private static void testRSAPrivateKeyGenerateAndExport() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", PROVIDER);
        kpg.initialize(4096);
        KeyPair kp = kpg.generateKeyPair();

        ensureKeyIsFromSunPKCS11(kp.getPublic());
        ensureKeyIsFromSunPKCS11(kp.getPrivate());
        Objects.requireNonNull(kp.getPrivate().getEncoded(),
                "Could not export private key");
    }

    private static void testDSAPrivateKeyImportAndExport() throws Exception {
        BigInteger privateValue = new BigInteger("776540688481433729664822401" +
                "5895780505054731336937960513928511924730");
        BigInteger prime = new BigInteger("1811184866314200557117877062488121" +
                "469659133925682350702354460589141170708161715231951918020125" +
                "044061516370042605439640379530343556410191905345983289013949" +
                "693393867000579961098176522028377556736148366264834033940522" +
                "034887130859362764707668940793187548340624431033792580942743" +
                "268186462355159813630244169054658542719322425431408825621271" +
                "898310513113877243465882037511173571044933151877685878679387" +
                "586541812442926940911875681284101907463100495640970687708161" +
                "261634790060655580211122402292101772553741704724263582994973" +
                "910927466649582620500210401035545698121102573881243308875710" +
                "2520562459649777989718122219159982614304359");
        BigInteger subPrime = new BigInteger("1968952686660515478851369357106" +
                "5914024068069442724893395618704484701");
        BigInteger base = new BigInteger("28592782376422019569310856110153890" +
                "879709181612975220235429003480877180630984239764282523693409" +
                "675060100542360520959501692726128314919022958356607477755729" +
                "347574741947393471158707232175605306725324048475087986519155" +
                "664345537298399718419039839162946924527602490198571084091890" +
                "169933809199002313226100830607842692992570749050436360297081" +
                "212880379097395596053478531748534102083342420277402756886984" +
                "618426376415660561656997337100438026971926964263608431736206" +
                "792141319514001488556117408586108219135730880594044593648923" +
                "730274929360377893370118757107592084984869086112619540269645" +
                "74111219599568903257472567764789616958430");

        KeyFactory kf = KeyFactory.getInstance("DSA", PROVIDER);
        PrivateKey pk = kf.generatePrivate(
                new DSAPrivateKeySpec(privateValue, prime, subPrime, base));

        ensureKeyIsFromSunPKCS11(pk);
        Objects.requireNonNull(pk.getEncoded(), "Could not export private key");
        DSAPrivateKey dsaPk = (DSAPrivateKey) pk;
        assertEquals(privateValue, dsaPk.getX(), "privateValue (X)");
        assertEquals(prime, dsaPk.getParams().getP(), "prime (P)");
        assertEquals(subPrime, dsaPk.getParams().getQ(), "subPrime (Q)");
        assertEquals(base, dsaPk.getParams().getG(), "base (G)");
    }

    private static void testDSAPrivateKeyGenerateAndExport() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA", PROVIDER);
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        ensureKeyIsFromSunPKCS11(kp.getPublic());
        ensureKeyIsFromSunPKCS11(kp.getPrivate());
        Objects.requireNonNull(kp.getPrivate().getEncoded(),
                "Could not export private key");
    }

    private static void testECPrivateKeyImportAndExport() throws Exception {
        AlgorithmParameters p = AlgorithmParameters.getInstance("EC", PROVIDER);
        p.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec params = p.getParameterSpec(ECParameterSpec.class);
        BigInteger privateValue = new BigInteger("655241821151813438841419350" +
                "61567659017866166973286609487826995518670289344152");

        KeyFactory kf = KeyFactory.getInstance("EC", PROVIDER);
        PrivateKey pk = kf.generatePrivate(
                new ECPrivateKeySpec(privateValue, params));

        ensureKeyIsFromSunPKCS11(pk);
        Objects.requireNonNull(pk.getEncoded(), "Could not export private key");
        ECPrivateKey ecPk = (ECPrivateKey) pk;
        assertEquals(privateValue, ecPk.getS(), "privateValue (S)");
        assertEquals(params.getCurve().getField(),
                ecPk.getParams().getCurve().getField(), "curve field");
        assertEquals(params.getCurve().getA(),
                ecPk.getParams().getCurve().getA(), "curve A");
        assertEquals(params.getCurve().getB(),
                ecPk.getParams().getCurve().getB(), "curve B");
        assertEquals(params.getGenerator().getAffineX(),
                ecPk.getParams().getGenerator().getAffineX(), "generator X");
        assertEquals(params.getGenerator().getAffineY(),
                ecPk.getParams().getGenerator().getAffineY(), "generator Y");
        assertEquals(params.getOrder(), ecPk.getParams().getOrder(), "order");
        assertEquals(params.getCofactor(), ecPk.getParams().getCofactor(),
                "cofactor");
    }

    private static void testECPrivateKeyGenerateAndExport() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", PROVIDER);
        kpg.initialize(new ECGenParameterSpec("secp521r1"));
        KeyPair kp = kpg.generateKeyPair();

        ensureKeyIsFromSunPKCS11(kp.getPublic());
        ensureKeyIsFromSunPKCS11(kp.getPrivate());
        Objects.requireNonNull(kp.getPrivate().getEncoded(),
                "Could not export private key");
    }

}
