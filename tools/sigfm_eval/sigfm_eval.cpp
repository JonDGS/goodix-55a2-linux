// Experiment 0017: offline preprocessing comparison for sigfm on the 55a2.
//
// Reads the .raw images listed in labels.txt (written by run-0017-capture.sh),
// builds each preprocessing variant, scores every press against every other
// press with sigfm and prints ONE JSON object of summary numbers per variant.
// No pixel values, keypoints, descriptors, file names or hashes are printed.
//
// Offline only: links OpenCV and sigfm, not libfprint or libusb, so it cannot
// open the reader. Build with build.sh against a libfprint checkout that has
// libfprint/sigfm (JonDGS/libfprint branch goodix55a2-sigfm).
//
// SPDX-License-Identifier: MIT

#include "sigfm.h"
#include "img-info.hpp"

#include <opencv2/core.hpp>
#include <opencv2/features2d.hpp>
#include <opencv2/imgproc.hpp>

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <map>
#include <random>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

namespace {

constexpr int RAW_LEN = 14788;          // plaintext image incl. 4-byte trailer
constexpr int PACKED_LEN = RAW_LEN - 4;  // 12-bit packed pixels
constexpr int W = 176, H = 56, NPIX = W * H;
constexpr int THRESHOLD = 24;            // driver's sigfm threshold (0016a)

struct Press {
    char finger;                 // 'A' or 'B'
    std::vector<int> nofinger;   // 12-bit, received order
    std::vector<int> finger_px;
};

[[noreturn]] void fail(const char* label)
{
    std::printf("{\"error\": \"%s\"}\n", label);
    std::exit(2);
}

// tlambertz capture.py unpack_data_to_16bit, as tools/goodix_handshake.py
std::vector<int> unpack(const unsigned char* b, int len)
{
    std::vector<int> out;
    out.reserve(len / 6 * 4);
    for (int i = 0; i + 6 <= len; i += 6) {
        const unsigned char* p = &b[i];
        out.push_back(((p[0] & 0xf) << 8) | p[1]);
        out.push_back((p[3] << 4) | (p[0] >> 4));
        out.push_back(((p[5] & 0xf) << 8) | p[2]);
        out.push_back((p[4] << 4) | (p[5] >> 4));
    }
    return out;
}

std::vector<int> read_raw(const std::string& path)
{
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f)
        fail("raw_open_failed");
    if (f.tellg() != RAW_LEN)
        fail("raw_wrong_length");
    f.seekg(0);
    std::vector<unsigned char> b(RAW_LEN);
    f.read(reinterpret_cast<char*>(b.data()), RAW_LEN);
    std::vector<int> out = unpack(b.data(), PACKED_LEN);
    std::fill(b.begin(), b.end(), 0);
    return out;
}

// Lambertz orientation flipud(reshape(176,56).T): index i = r*56 + c goes to
// row (55 - c), column r of a 56x176 image. Same as goodix55a2.c build_image.
int oriented_index(int i) { return (H - 1 - i % H) * W + i / H; }

struct Diff {
    cv::Mat d;      // CV_32F, oriented, invalid pixels set to the median
    cv::Mat valid;  // CV_8U, 255 where both frames are nonzero
};

float percentile(std::vector<float> v, double p)
{
    if (v.empty())
        return 0;
    size_t k = static_cast<size_t>((v.size() - 1) * p);
    std::nth_element(v.begin(), v.begin() + k, v.end());
    return v[k];
}

Diff make_diff(const Press& pr)
{
    Diff r{cv::Mat(H, W, CV_32F), cv::Mat(H, W, CV_8U)};
    std::vector<float> vals;
    for (int i = 0; i < NPIX; i++)
        if (pr.nofinger[i] && pr.finger_px[i])
            vals.push_back(float(pr.nofinger[i] - pr.finger_px[i]));
    float med = percentile(vals, 0.5);
    for (int i = 0; i < NPIX; i++) {
        bool ok = pr.nofinger[i] && pr.finger_px[i];
        int o = oriented_index(i);
        r.d.at<float>(o / W, o % W) = ok ? float(pr.nofinger[i] - pr.finger_px[i]) : med;
        r.valid.at<unsigned char>(o / W, o % W) = ok ? 255 : 0;
    }
    return r;
}

cv::Mat stretch(const cv::Mat& f, float lo, float hi)
{
    cv::Mat out;
    double a = hi > lo ? 255.0 / (hi - lo) : 0;
    f.convertTo(out, CV_8U, a, -lo * a);  // saturating
    return out;
}

std::pair<float, float> lo_hi(const cv::Mat& f)
{
    std::vector<float> v(f.begin<float>(), f.end<float>());
    return {percentile(v, 0.01), percentile(v, 0.99)};
}

cv::Mat v0(const Diff& d)
{
    auto [lo, hi] = lo_hi(d.d);
    return stretch(d.d, lo, hi);
}

cv::Mat bandpass(const Diff& d)
{
    // Difference of Gaussians: keep ridge-scale detail, drop smooth
    // background. Sigmas fixed before scoring (plan 0017).
    cv::Mat a, b;
    cv::GaussianBlur(d.d, a, cv::Size(0, 0), 1.0);
    cv::GaussianBlur(d.d, b, cv::Size(0, 0), 4.0);
    cv::Mat dog = a - b;
    auto [lo, hi] = lo_hi(dog);
    return stretch(dog, lo, hi);
}

struct Variant {
    std::string name;
    std::vector<SigfmImgInfo*> info;
    std::vector<int> keypoints;
};

SigfmImgInfo* extract_masked(const cv::Mat& img, const cv::Mat& mask)
{
    std::vector<cv::KeyPoint> pts;
    cv::Mat descs;
    cv::SIFT::create()->detectAndCompute(img, mask, pts, descs);
    return new SigfmImgInfo{pts, descs};
}

void dump_pgm(const std::string& dir, const std::string& variant, size_t idx, const cv::Mat& img)
{
    std::ostringstream name;
    name << dir << "/" << variant << "-" << idx << ".pgm";
    int fd = ::open(name.str().c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0)
        fail("dump_open_failed");
    std::string hdr = "P5\n" + std::to_string(img.cols) + " " + std::to_string(img.rows) + "\n255\n";
    bool ok = ::write(fd, hdr.data(), hdr.size()) == ssize_t(hdr.size());
    for (int r = 0; ok && r < img.rows; r++)
        ok = ::write(fd, img.ptr(r), img.cols) == img.cols;
    ::close(fd);
    if (!ok)
        fail("dump_write_failed");
}

struct Stats {
    double min = 0, median = 0, max = 0;
};

Stats stats(std::vector<int> v)
{
    Stats s;
    if (v.empty())
        return s;
    std::sort(v.begin(), v.end());
    s.min = v.front();
    s.max = v.back();
    s.median = v[(v.size() - 1) / 2];
    return s;
}

// Score every ordered pair; genuine = same finger, impostor = different.
std::string evaluate(const Variant& v, const std::vector<char>& fingers)
{
    size_t n = v.info.size();
    std::vector<int> gen, imp;
    std::vector<int> best_gen;  // best genuine score per A press (multi-template)
    int errors = 0;
    for (size_t i = 0; i < n; i++)
        for (size_t j = 0; j < n; j++) {
            if (i == j)
                continue;
            if (fingers[i] == 'A' && best_gen.size() <= i)
                best_gen.resize(i + 1, -1);
            int s = sigfm_match_score(v.info[i], v.info[j]);
            if (s < 0) {
                errors++;
                continue;
            }
            // Plan 0017: genuine = A-A, impostor = A-B (B is the other finger,
            // so B-B pairs are not counted).
            if (fingers[i] == 'A' && fingers[j] == 'A') {
                gen.push_back(s);
                best_gen[i] = std::max(best_gen[i], s);
            } else if (fingers[i] != fingers[j]) {
                imp.push_back(s);
            }
        }
    std::vector<int> best;
    for (int b : best_gen)
        if (b >= 0)
            best.push_back(b);
    Stats g = stats(gen), im = stats(imp), kp = stats(v.keypoints);
    int t0 = int(im.max) + 1;  // lowest threshold with zero impostor accepts
    auto rate = [](const std::vector<int>& xs, int t) {
        if (xs.empty())
            return 0.0;
        return double(std::count_if(xs.begin(), xs.end(), [t](int x) { return x >= t; })) / xs.size();
    };
    std::ostringstream o;
    o.setf(std::ios::fixed);
    o.precision(3);
    o << "{\"variant\": \"" << v.name << "\""
      << ", \"keypoints\": [" << kp.min << ", " << kp.median << ", " << kp.max << "]"
      << ", \"genuine_pairs\": " << gen.size()
      << ", \"impostor_pairs\": " << imp.size()
      << ", \"score_errors\": " << errors
      << ", \"genuine_min_med_max\": [" << g.min << ", " << g.median << ", " << g.max << "]"
      << ", \"impostor_min_med_max\": [" << im.min << ", " << im.median << ", " << im.max << "]"
      << ", \"genuine_rate_at_24\": " << rate(gen, THRESHOLD)
      << ", \"impostor_rate_at_24\": " << rate(imp, THRESHOLD)
      << ", \"zero_impostor_threshold\": " << t0
      << ", \"genuine_rate_at_zero_impostor\": " << rate(gen, t0)
      << ", \"press_best_match_rate_at_zero_impostor\": " << rate(best, t0)
      << "}";
    return o.str();
}

void free_variant(Variant& v)
{
    for (auto* p : v.info)
        sigfm_free_info(p);
    v.info.clear();
}

std::vector<Variant> build_variants(const std::vector<Press>& presses, const std::string& dump_dir)
{
    std::vector<Diff> diffs;
    for (const auto& p : presses)
        diffs.push_back(make_diff(p));

    // V1: one gain/offset for the whole set = median of per-image percentiles.
    std::vector<float> los, his;
    for (const auto& d : diffs) {
        auto [lo, hi] = lo_hi(d.d);
        los.push_back(lo);
        his.push_back(hi);
    }
    float glo = percentile(los, 0.5), ghi = percentile(his, 0.5);

    auto clahe = cv::createCLAHE(2.0, cv::Size(8, 2));
    const char* names[] = {"V0_baseline", "V1_fixed_stretch", "V2_clahe",
                           "V3_bandpass", "V4_bandpass_2x", "V5_bandpass_masked"};
    std::vector<Variant> vs;
    for (auto* nm : names)
        vs.push_back(Variant{nm, {}, {}});

    for (size_t i = 0; i < diffs.size(); i++) {
        const Diff& d = diffs[i];
        cv::Mat img[6];
        img[0] = v0(d);
        img[1] = stretch(d.d, glo, ghi);
        clahe->apply(img[0], img[2]);
        img[3] = bandpass(d);
        cv::resize(img[3], img[4], cv::Size(), 2.0, 2.0, cv::INTER_CUBIC);
        img[5] = img[3];

        // V5 mask: drop a 4 px border and dead pixels grown by 2 px.
        cv::Mat dead, mask(H, W, CV_8U, cv::Scalar(0));
        cv::bitwise_not(d.valid, dead);
        cv::dilate(dead, dead, cv::getStructuringElement(cv::MORPH_RECT, cv::Size(5, 5)));
        mask(cv::Rect(4, 4, W - 8, H - 8)).setTo(255);
        mask.setTo(0, dead);

        for (int k = 0; k < 6; k++) {
            if (!img[k].isContinuous())
                img[k] = img[k].clone();
            SigfmImgInfo* info = k == 5 ? extract_masked(img[k], mask)
                                        : sigfm_extract(img[k].ptr(), img[k].cols, img[k].rows);
            if (!info)
                fail("extract_failed");
            vs[k].info.push_back(info);
            vs[k].keypoints.push_back(sigfm_keypoints_count(info));
            if (!dump_dir.empty())
                dump_pgm(dump_dir, vs[k].name, i, img[k]);
        }
    }
    return vs;
}

// --baseline fresh (default): each press uses the newest preceding no-finger
// image. --baseline first: every press uses the first no-finger image of the
// set, modelling the driver's single calibration image taken at activation.
int run_labels(const std::string& dir, const std::string& dump_dir, bool first_baseline)
{
    std::ifstream lf(dir + "/labels.txt");
    if (!lf)
        fail("labels_missing");
    std::vector<Press> presses;
    std::vector<int> current_nofinger;
    std::string base, label;
    int nofinger_count = 0;
    while (lf >> base >> label) {
        if (base.find('/') != std::string::npos || base.find("..") != std::string::npos)
            fail("labels_bad_name");
        if (label == "nofinger") {
            if (!first_baseline || current_nofinger.empty())
                current_nofinger = read_raw(dir + "/" + base + ".raw");
            nofinger_count++;
        } else if (label == "A" || label == "B") {
            if (current_nofinger.empty())
                fail("finger_before_nofinger");
            presses.push_back(Press{label[0], current_nofinger, read_raw(dir + "/" + base + ".raw")});
        } else {
            fail("labels_bad_label");
        }
    }
    std::vector<char> fingers;
    for (auto& p : presses)
        fingers.push_back(p.finger);
    long na = std::count(fingers.begin(), fingers.end(), 'A');
    long nb = std::count(fingers.begin(), fingers.end(), 'B');
    if (na < 2 || nb < 1)
        fail("too_few_presses");

    auto vs = build_variants(presses, dump_dir);
    for (auto& p : presses) {
        std::fill(p.nofinger.begin(), p.nofinger.end(), 0);
        std::fill(p.finger_px.begin(), p.finger_px.end(), 0);
    }
    std::printf("{\"presses_A\": %ld, \"presses_B\": %ld, \"nofinger\": %d, \"threshold\": %d, \"baseline\": \"%s\"}\n",
                na, nb, nofinger_count, THRESHOLD, first_baseline ? "first" : "fresh");
    for (auto& v : vs) {
        std::printf("%s\n", evaluate(v, fingers).c_str());
        std::fflush(stdout);
        free_variant(v);
    }
    return 0;
}

// --self-test: synthetic ridge fields only, no real data. Two "fingers" are
// different random fields; presses are shifted crops of one field. Checks
// that the variant pipeline runs and that genuine scores beat impostors on
// synthetic data for the baseline variant.
std::vector<int> pack_to_pixels_roundtrip_check()
{
    // Pack 4 known 12-bit values the way the device does and unpack them.
    int v[4] = {0x123, 0x456, 0x789, 0xabc};
    unsigned char b[6];
    b[0] = (v[0] >> 8) | ((v[1] & 0xf) << 4);
    b[1] = v[0] & 0xff;
    b[2] = v[2] & 0xff;
    b[3] = v[1] >> 4;
    b[4] = v[3] >> 4;
    b[5] = (v[2] >> 8) | ((v[3] & 0xf) << 4);
    return unpack(b, 6);
}

cv::Mat ridge_field(unsigned seed, int w, int h)
{
    std::mt19937 rng(seed);
    std::uniform_real_distribution<float> u(0, 1);
    cv::Mat f(h, w, CV_32F);
    float cx = w * (0.3f + 0.4f * u(rng)), cy = h * (0.3f + 0.4f * u(rng));
    float k = 0.55f + 0.2f * u(rng), wob = 3 + 4 * u(rng);
    for (int y = 0; y < h; y++)
        for (int x = 0; x < w; x++) {
            float r = std::hypot(x - cx, (y - cy) * 1.4f);
            float a = std::atan2(y - cy, x - cx);
            f.at<float>(y, x) = std::sin(k * r + wob * std::sin(3 * a));
        }
    cv::Mat noise(h, w, CV_32F);
    cv::randn(noise, 0, 0.15);
    return f + noise;
}

Press synth_press(char finger, const cv::Mat& field, int ox, int oy)
{
    Press p{finger, std::vector<int>(NPIX), std::vector<int>(NPIX)};
    for (int i = 0; i < NPIX; i++) {
        int o = oriented_index(i);
        float v = field.at<float>(oy + o / W, ox + o % W);
        p.nofinger[i] = 3000;
        p.finger_px[i] = 3000 - int(800 + 600 * v);
    }
    return p;
}

int self_test()
{
    int fails = 0;
    auto rt = pack_to_pixels_roundtrip_check();
    if (rt != std::vector<int>{0x123, 0x456, 0x789, 0xabc})
        fails++, std::printf("FAIL unpack\n");
    // Orientation: a bijection onto the 176x56 grid.
    std::vector<int> seen(NPIX, 0);
    for (int i = 0; i < NPIX; i++)
        seen[oriented_index(i)]++;
    if (std::count(seen.begin(), seen.end(), 1) != NPIX)
        fails++, std::printf("FAIL orientation\n");
    if (oriented_index(0) != (H - 1) * W || oriented_index(H - 1) != 0)
        fails++, std::printf("FAIL orientation corners\n");

    cv::Mat fa = ridge_field(1, W + 40, H + 20), fb = ridge_field(2, W + 40, H + 20);
    std::vector<Press> ps;
    int offs[][2] = {{0, 0}, {6, 3}, {12, 6}, {18, 9}, {24, 12}};
    for (auto& o : offs)
        ps.push_back(synth_press('A', fa, o[0], o[1]));
    for (auto& o : offs)
        ps.push_back(synth_press('B', fb, o[0], o[1]));
    std::vector<char> fingers;
    for (auto& p : ps)
        fingers.push_back(p.finger);
    auto vs = build_variants(ps, "");
    if (vs.size() != 6)
        fails++, std::printf("FAIL variant count\n");
    // Baseline genuine median must exceed impostor median on synthetic data.
    {
        std::vector<int> g, im;
        for (size_t i = 0; i < ps.size(); i++)
            for (size_t j = 0; j < ps.size(); j++)
                if (i != j)
                    (fingers[i] == fingers[j] ? g : im).push_back(sigfm_match_score(vs[0].info[i], vs[0].info[j]));
        if (!(stats(g).median > stats(im).median))
            fails++, std::printf("FAIL synthetic separation g=%g i=%g\n", stats(g).median, stats(im).median);
    }
    for (auto& v : vs) {
        std::string line = evaluate(v, fingers);
        if (line.find("\"variant\"") == std::string::npos)
            fails++, std::printf("FAIL evaluate output\n");
        free_variant(v);
    }
    std::printf(fails ? "self-test FAILED (%d)\n" : "self-test OK\n", fails);
    return fails ? 1 : 0;
}

}  // namespace

int main(int argc, char** argv)
{
    std::string dir, dump;
    bool first_baseline = false;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--self-test")
            return self_test();
        else if (a == "--baseline" && i + 1 < argc) {
            std::string b = argv[++i];
            if (b == "first")
                first_baseline = true;
            else if (b != "fresh")
                fail("usage");
        }
        else if (a == "--dump-pgm" && i + 1 < argc)
            dump = argv[++i];
        else if (dir.empty() && a.rfind("--", 0) != 0)
            dir = a;
        else
            fail("usage");
    }
    if (dir.empty())
        fail("usage");
    return run_labels(dir, dump, first_baseline);
}
