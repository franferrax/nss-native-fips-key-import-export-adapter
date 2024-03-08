// SPDX-License-Identifier: GPL-2.0-or-later WITH Classpath-exception-2.0

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
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
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
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
    private static final String FIPS_PROVIDER = "SunPKCS11-" + CFG_NAME_SUFFIX;
    private static final int WRAP_ROWS = 80;
    private static final String DATA_GENERATION_MODE_ARG = "--data-generation";
    // Randomly generated in a jshell shell with:
    // new BigInteger(new FileInputStream("/dev/random").readNBytes(32))
    private static final BigInteger MESSAGE = new BigInteger("-23082341565882" +
            "443623706316180041238354969940441294942554491935720154682342904");
    // Randomly generated in a jshell shell with:
    // new BigInteger(new FileInputStream("/dev/random").readNBytes(16))
    private static final IvParameterSpec IV = new IvParameterSpec(new BigInteger
            ("24474587988484301349380487490566153560").toByteArray());
    private static boolean dataGenerationMode = false;

    private static void initializeFIPS(String nssAdapterLib) throws Exception {
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

        // Insert our customized SunPKCS11 provider as the first one
        String SunPKCS11 = System.getProperty("java.version").startsWith("1.") ?
                "sun.security.pkcs11.SunPKCS11" : // <-- Java 8
                "SunPKCS11";
        int n = 1;
        String previous = SunPKCS11 + " " + cfg;
        while (previous != null) {
            String current = Security.getProperty("security.provider." + n);
            Security.setProperty("security.provider." + n++, previous);
            previous = current;
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            throw new Exception("A *.so library program argument is required " +
                    "(or the " + DATA_GENERATION_MODE_ARG + " argument)");
        }
        dataGenerationMode = DATA_GENERATION_MODE_ARG.equals(args[0]);
        if (!dataGenerationMode) {
            initializeFIPS(args[0]);
        }
        for (Method method : Main.class.getDeclaredMethods()) {
            if (method.getName().startsWith(TESTS_METHODS_PREFIX)) {
                printDescription(method);
                method.invoke(null);
            }
        }
        System.out.println(SEPARATOR);
        System.out.println("TEST PASS - OK");
    }

    @SuppressWarnings("unchecked")
    private static <T> T getInstance(Class<T> serviceClass, String algorithm)
            throws Exception {
        if (dataGenerationMode) {
            return (T) serviceClass.getDeclaredMethod("getInstance",
                    String.class).invoke(null, algorithm);

        } else {
            return (T) serviceClass.getDeclaredMethod("getInstance",
                            String.class, String.class)
                    .invoke(null, algorithm, FIPS_PROVIDER);
        }
    }

    private static void printDescription(Method method) {
        String desc = method.getName().substring(TESTS_METHODS_PREFIX.length());
        StringBuilder sb = new StringBuilder(SEPARATOR);
        sb.append(System.lineSeparator());
        int mark = sb.length();
        sb.append(' ');
        for (String word : CAMEL_CASE_SPLITTER.split(desc)) {
            sb.append(word).append(' ');
        }
        sb.deleteCharAt(sb.length() - 1);
        sb.append(System.lineSeparator());
        mark -= sb.length();
        while (mark++ < 0) {
            sb.append('-');
        }
        System.out.println(sb);
    }

    private static void assertEquals(Object expected, Object actual,
            String desc) throws Exception {
        if (!Objects.equals(actual, expected)) {
            throw new Exception("Unexpected " + desc + " (found: " + actual +
                    ", but was expecting: " + expected + ")");
        }
    }

    private static void checkKeyClass(Object key) throws Exception {
        boolean isP11Key = key.getClass().toString().contains("P11Key");
        if (dataGenerationMode && isP11Key) {
            throw new Exception("When in data generation mode, the key should" +
                    " NOT be a P11Key (key class: " + key.getClass() + ")");
        }
        if (!dataGenerationMode && !isP11Key) {
            throw new Exception("The key should be a P11Key from the " +
                    "SunPKCS11 provider (key class: " + key.getClass() + ")");
        }
    }

    private static byte[] doSign(String algorithm, PrivateKey prvK)
            throws Exception {
        Signature sig = getInstance(Signature.class, algorithm);
        sig.initSign(prvK);
        sig.update(MESSAGE.toByteArray());
        return sig.sign();
    }

    private static void checkSign(String algorithm, String crossCheckProvider,
            PrivateKey prvK, PublicKey pubK, String expectedSignature)
            throws Exception {
        // Execute two sign operations in a row to exercise
        // PKCS11::getNativeKeyInfo and PKCS11::createNativeKey
        // code (JDK-6913047).
        byte[] performedSignature = doSign(algorithm, prvK);
        performedSignature = doSign(algorithm, prvK);

        if (expectedSignature != null) {
            assertEquals(new BigInteger(expectedSignature),
                    new BigInteger(performedSignature),
                    algorithm + " signature");
        }

        // Cross-check by verifying the signature with a non-FIPS provider
        Signature sig = Signature.getInstance(algorithm, crossCheckProvider);
        sig.initVerify(pubK);
        sig.update(MESSAGE.toByteArray());
        if (!sig.verify(performedSignature)) {
            throw new Exception("Signature cross-provider check failed");
        }
    }

    private static byte[] doCipher(String algorithm, SecretKey key)
            throws Exception {
        Cipher cipher = getInstance(Cipher.class, algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, IV);
        return cipher.doFinal(MESSAGE.toByteArray());
    }

    private static void checkCipher(String algorithm, String crossCheckProvider,
            SecretKey key, String expectedCipherText) throws Exception {
        // Execute two encryption operations in a row to exercise
        // PKCS11::getNativeKeyInfo and PKCS11::createNativeKey
        // code (JDK-6913047).
        byte[] cipherText = doCipher(algorithm, key);
        cipherText = doCipher(algorithm, key);

        if (expectedCipherText != null) {
            assertEquals(new BigInteger(expectedCipherText),
                    new BigInteger(cipherText), "cipher text");
        }

        // Cross-check by decrypting the cipher text with a non-FIPS provider
        Cipher cipher = Cipher.getInstance(algorithm, crossCheckProvider);
        cipher.init(Cipher.DECRYPT_MODE, key, IV);
        byte[] actualPlainText = cipher.doFinal(cipherText);
        assertEquals(MESSAGE, new BigInteger(actualPlainText),
                "cross-provider decrypted message");
    }

    private static void logAsBI(String varName, BigInteger number) {
        logWrapped("        BigInteger " + varName + " = new BigInteger(\"",
                number);
    }

    private static void logWrapped(String head, BigInteger number) {
        String digits = number.toString();
        while (true) {
            int length = WRAP_ROWS - head.length() - 3;
            if (digits.length() > length) {
                System.out.println(head + digits.substring(0, length) + "\" +");
                head = "                \"";
            } else {
                System.out.println(head + digits + "\");");
                break;
            }
            digits = digits.substring(length);
        }
    }

    private static void testSecretKeyImportAndExport() throws Exception {
        // Symmetric 256 key (randomly generated in a non-FIPS machine with
        // 'make test-data' from testSecretKeyGenerateAndExport)
        BigInteger rawKey = new BigInteger("331609782999261118064459749711703" +
                "22140116389299700518577411521037425918595095");

        SecretKey key = new SecretKeySpec(rawKey.toByteArray(), "AES");
        if (!dataGenerationMode) {
            // SunPKCS11 is the only provider that has an AES SecretKeyFactory.
            SecretKeyFactory skf = getInstance(SecretKeyFactory.class, "AES");
            key = skf.translateKey(key);
        }

        checkKeyClass(key);
        byte[] exported = key.getEncoded();
        Objects.requireNonNull(exported, "Export failed");
        assertEquals(rawKey, new BigInteger(exported), "key bytes");

        checkCipher("AES/CBC/PKCS5Padding", "SunJCE", key, "30621773074265860" +
                "449352098114637781899050134172166402061231870784000850592602" +
                "53549466675678934238030319927256335238");
    }

    private static void testSecretKeyGenerateAndExport() throws Exception {
        int keyBytes = 32;

        KeyGenerator kg = getInstance(KeyGenerator.class, "AES");
        kg.init(keyBytes << 3);
        SecretKey key = kg.generateKey();

        checkKeyClass(key);
        byte[] exported = key.getEncoded();
        Objects.requireNonNull(exported, "Export failed");
        assertEquals(keyBytes, exported.length, "key length");
        checkCipher("AES/CBC/PKCS5Padding", "SunJCE", key, null);

        if (dataGenerationMode) {
            logAsBI("rawKey", new BigInteger(exported));

            System.out.println(System.lineSeparator());
            String cipherAlg = "AES/CBC/PKCS5Padding";
            logWrapped("        checkCipher(\"" + cipherAlg +
                            "\", \"SunJCE\", key, \"",
                    new BigInteger(doCipher(cipherAlg, key)));
        }
    }

    private static void testRSAPrivateKeyImportAndExport() throws Exception {
        // RSA 4096 key pair (randomly generated in a non-FIPS machine with
        // 'make test-data' from testRSAPrivateKeyGenerateAndExport)
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

        KeyFactory kf = getInstance(KeyFactory.class, "RSA");
        RSAPrivateCrtKey prvK = (RSAPrivateCrtKey) kf.generatePrivate(
                new RSAPrivateCrtKeySpec(modulus, publicExponent,
                        privateExponent, prime1, prime2, primeExponent1,
                        primeExponent2, coefficient));

        checkKeyClass(prvK);
        Objects.requireNonNull(prvK.getEncoded(), "Export failed");
        assertEquals(modulus, prvK.getModulus(), "modulus");
        assertEquals(publicExponent, prvK.getPublicExponent(),
                "publicExponent");
        assertEquals(privateExponent, prvK.getPrivateExponent(),
                "privateExponent");
        assertEquals(prime1, prvK.getPrimeP(), "prime1 (primeP)");
        assertEquals(prime2, prvK.getPrimeQ(), "prime2 (primeQ)");
        assertEquals(primeExponent1, prvK.getPrimeExponentP(),
                "primeExponent1 (primeExponentP)");
        assertEquals(primeExponent2, prvK.getPrimeExponentQ(),
                "primeExponent2 (primeExponentQ)");
        assertEquals(coefficient, prvK.getCrtCoefficient(), "coefficient");

        RSAPublicKey pubK = (RSAPublicKey) kf.generatePublic(
                new RSAPublicKeySpec(modulus, publicExponent));
        checkKeyClass(pubK);
        checkSign("SHA256withRSA", "SunRsaSign", prvK, pubK, "131006121476913" +
                "616162554435994735147036148721299791109201022900484794240189" +
                "446997816349280256804052535569431102926413215238656615032576" +
                "366620417892310212909741856551115382333224614472355009168639" +
                "749882364824456201224538229877928172011098827766075995231867" +
                "688557575826972210188866951625811233271012228661645162064598" +
                "362274797087543684976229458569066402665623282841712188861773" +
                "010532198001627187292140382774007829225068243521647933579502" +
                "666117339874055467522172042123295824082932995321111581205033" +
                "393976939370264501519923035128508492203866239518985420059605" +
                "660475338564935484843279185097985814669917301227141459550251" +
                "116146867544423778796236606092075482124616151535586719199506" +
                "311947299033392550301698164701822621870274006806327272952747" +
                "535907873007572014548600225907689955836908383307420889823720" +
                "170415284440827647286190078805258907754803259829134834958965" +
                "801773390150528790741261013568090708575663619521608546495314" +
                "074813701316659123927460503617119262700540577018931514443944" +
                "301823287790066783159467839469678954387231209115428534757337" +
                "793797451811649451993891003672516121318347732500349040371892" +
                "672237054298606892251178204557343158661838464199992690335697" +
                "213619956921949336607557030764525729824877153973937027344246" +
                "516276343010274809");
    }

    private static void testRSAPrivateKeyGenerateAndExport() throws Exception {
        KeyPairGenerator kpg = getInstance(KeyPairGenerator.class, "RSA");
        kpg.initialize(4096);
        KeyPair kp = kpg.generateKeyPair();

        RSAPublicKey pubK = (RSAPublicKey) kp.getPublic();
        RSAPrivateCrtKey prvK = (RSAPrivateCrtKey) kp.getPrivate();
        checkKeyClass(pubK);
        checkKeyClass(prvK);
        Objects.requireNonNull(prvK.getEncoded(), "Export failed");
        checkSign("SHA256withRSA", "SunRsaSign", prvK, pubK, null);

        if (dataGenerationMode) {
            logAsBI("modulus", prvK.getModulus());
            logAsBI("publicExponent", prvK.getPublicExponent());
            logAsBI("privateExponent", prvK.getPrivateExponent());
            logAsBI("prime1", prvK.getPrimeP());
            logAsBI("prime2", prvK.getPrimeQ());
            logAsBI("primeExponent1", prvK.getPrimeExponentP());
            logAsBI("primeExponent2", prvK.getPrimeExponentQ());
            logAsBI("coefficient", prvK.getCrtCoefficient());

            System.out.println(System.lineSeparator());
            String signAlg = "SHA256withRSA";
            logWrapped("        checkSign(\"" + signAlg +
                            "\", \"SunRsaSign\", prvK, pubK, \"",
                    new BigInteger(doSign(signAlg, prvK)));
        }
    }

    private static void testDSAPrivateKeyImportAndExport() throws Exception {
        // DSA 1024 key pair (randomly generated in a non-FIPS machine with
        // 'make test-data' from testDSAPrivateKeyGenerateAndExport)
        BigInteger publicValue = new BigInteger("1495744577618661430190874954" +
                "934393034736152170302901636921673268470680617615407955608256" +
                "761322154063238150781245162523249568226692166493988126351162" +
                "903284160178231356993835325966499190537082954899849614357596" +
                "314453421730734987965693884894593276653904413363975559818249" +
                "74730699583555497125776622730590991985356");
        BigInteger privateValue = new BigInteger("835414315914508000223458233" +
                "143984751518292697709");
        BigInteger prime = new BigInteger("1780119054785422665282375624501599" +
                "901452321563691206742732744503144428657887370207706126952521" +
                "234630795671567847784664499706507709207278570500096683881440" +
                "341297452211718185060472311500393010799593580673953487170663" +
                "198022620197149665241350609459137075949565146728556906067941" +
                "35837542707371727429551343320695239");
        BigInteger subPrime = new BigInteger("8642054956048074761205726160179" +
                "55259175325408501");
        BigInteger base = new BigInteger("17406820753240209518581198012352343" +
                "653860449079456135097849583104059995348845582314785159740894" +
                "095072530779709491575949236830057425243876103708447346718014" +
                "887611810308304375498519098347260155049469132948808339549231" +
                "385000036164648264460849230407872181895999905649609776936801" +
                "7749273708962006689187956744210730");

        KeyFactory kf = getInstance(KeyFactory.class, "DSA");
        DSAPrivateKey prvK = (DSAPrivateKey) kf.generatePrivate(
                new DSAPrivateKeySpec(privateValue, prime, subPrime, base));

        checkKeyClass(prvK);
        Objects.requireNonNull(prvK.getEncoded(), "Export failed");
        assertEquals(privateValue, prvK.getX(), "privateValue (X)");
        assertEquals(prime, prvK.getParams().getP(), "prime (P)");
        assertEquals(subPrime, prvK.getParams().getQ(), "subPrime (Q)");
        assertEquals(base, prvK.getParams().getG(), "base (G)");

        DSAPublicKey pubK = (DSAPublicKey) kf.generatePublic(
                new DSAPublicKeySpec(publicValue, prime, subPrime, base));
        checkKeyClass(pubK);
        checkSign("SHA1withDSA", "SUN", prvK, pubK, null);
    }

    private static void testDSAPrivateKeyGenerateAndExport() throws Exception {
        KeyPairGenerator kpg = getInstance(KeyPairGenerator.class, "DSA");
        kpg.initialize(1024);
        KeyPair kp = kpg.generateKeyPair();

        DSAPublicKey pubK = (DSAPublicKey) kp.getPublic();
        DSAPrivateKey prvK = (DSAPrivateKey) kp.getPrivate();
        checkKeyClass(pubK);
        checkKeyClass(prvK);
        Objects.requireNonNull(prvK.getEncoded(), "Export failed");
        checkSign("SHA1withDSA", "SUN", prvK, pubK, null);

        if (dataGenerationMode) {
            logAsBI("publicValue", pubK.getY());
            logAsBI("privateValue", prvK.getX());
            logAsBI("prime", prvK.getParams().getP());
            logAsBI("subPrime", prvK.getParams().getQ());
            logAsBI("base", prvK.getParams().getG());
        }
    }

    private static void testECPrivateKeyImportAndExport() throws Exception {
        // EC secp256r1 key pair (randomly generated in a non-FIPS machine with
        // 'make test-data' from testECPrivateKeyGenerateAndExport)
        AlgorithmParameters p = getInstance(AlgorithmParameters.class, "EC");
        p.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec params = p.getParameterSpec(ECParameterSpec.class);
        BigInteger publicX = new BigInteger("93062551683536377350716644831279" +
                "570345944186988487518330597599802522368092364");
        BigInteger publicY = new BigInteger("69914441280610907160365037474212" +
                "863551346530835322446220875816596067599130846");
        ECPoint publicPoint = new ECPoint(publicX, publicY);
        BigInteger privateValue = new BigInteger("394304154275358840373799541" +
                "50072853733096533150596936863525916096810784089027");

        KeyFactory kf = getInstance(KeyFactory.class, "EC");
        ECPrivateKey prvK = (ECPrivateKey) kf.generatePrivate(
                new ECPrivateKeySpec(privateValue, params));

        checkKeyClass(prvK);
        Objects.requireNonNull(prvK.getEncoded(), "Export failed");
        assertEquals(privateValue, prvK.getS(), "privateValue (S)");
        assertEquals(params.getCurve().getField(),
                prvK.getParams().getCurve().getField(), "curve field");
        assertEquals(params.getCurve().getA(),
                prvK.getParams().getCurve().getA(), "curve A");
        assertEquals(params.getCurve().getB(),
                prvK.getParams().getCurve().getB(), "curve B");
        assertEquals(params.getGenerator().getAffineX(),
                prvK.getParams().getGenerator().getAffineX(), "generator X");
        assertEquals(params.getGenerator().getAffineY(),
                prvK.getParams().getGenerator().getAffineY(), "generator Y");
        assertEquals(params.getOrder(), prvK.getParams().getOrder(), "order");
        assertEquals(params.getCofactor(), prvK.getParams().getCofactor(),
                "cofactor");

        ECPublicKey pubK = (ECPublicKey) kf.generatePublic(
                new ECPublicKeySpec(publicPoint, params));
        checkKeyClass(pubK);
        checkSign("SHA256withECDSA", "SunEC", prvK, pubK, null);
    }

    private static void testECPrivateKeyGenerateAndExport() throws Exception {
        KeyPairGenerator kpg = getInstance(KeyPairGenerator.class, "EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();

        ECPublicKey pubK = (ECPublicKey) kp.getPublic();
        ECPrivateKey prvK = (ECPrivateKey) kp.getPrivate();
        checkKeyClass(pubK);
        checkKeyClass(prvK);
        Objects.requireNonNull(prvK.getEncoded(), "Export failed");
        checkSign("SHA256withECDSA", "SunEC", prvK, pubK, null);

        if (dataGenerationMode) {
            logAsBI("publicX", pubK.getW().getAffineX());
            logAsBI("publicY", pubK.getW().getAffineY());
            System.out.println("        ECPoint publicPoint = " +
                    "new ECPoint(publicX, publicY);");
            logAsBI("privateValue", prvK.getS());
        }
    }
}
